import "dotenv/config";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const roles = ["admin", "operator", "accounts"];
app.use(cors({ origin: process.env.CLIENT_URL || "http://localhost:5173" }));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: roles, default: "operator" },
    resetToken: String,
    resetExpires: Date,
  },
  { timestamps: true },
);
const partySchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    type: {
      type: String,
      enum: ["Customer", "Vendor", "Other"],
      default: "Customer",
    },
    phone: String,
    email: String,
    taxId: String,
    address: String,
    active: { type: Boolean, default: true },
  },
  { timestamps: true },
);
const transactionSchema = new mongoose.Schema(
  {
    direction: {
      type: String,
      enum: ["received", "transferred"],
      required: true,
    },
    amount: { type: Number, required: true, min: 0 },
    currency: { type: String, default: "INR" },
    mode: {
      type: String,
      enum: ["Bank Transfer", "Cash", "Cheque", "UPI", "Card"],
      required: true,
    },
    party: { type: mongoose.Schema.Types.ObjectId, ref: "Party" },
    reference: String,
    notes: String,
    attachment: String,
    transactionDate: { type: Date, default: Date.now },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true },
);
const User = mongoose.model("User", userSchema);
const Party = mongoose.model("Party", partySchema);
const Transaction = mongoose.model("Transaction", transactionSchema);

const sign = (user) =>
  jwt.sign(
    { id: user._id, role: user.role, name: user.name },
    process.env.JWT_SECRET || "dev-secret-change-me",
    { expiresIn: "8h" },
  );
const auth =
  (...allowed) =>
  async (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET || "dev-secret-change-me",
      );
      req.user = await User.findById(decoded.id).select("-password");
      if (!req.user || (allowed.length && !allowed.includes(req.user.role)))
        return res.status(403).json({ message: "Access denied" });
      next();
    } catch {
      res.status(401).json({ message: "Please sign in again" });
    }
  };
const storage = multer.diskStorage({
  destination: path.join(__dirname, "uploads"),
  filename: (req, file, cb) =>
    cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "-")}`),
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

app.post("/api/auth/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password)))
    return res.status(401).json({ message: "Invalid email or password" });
  res.json({
    token: sign(user),
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
  });
});
app.post("/api/auth/forgot-password", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return res.json({
      message: "If that account exists, a reset link has been created.",
    });
  user.resetToken = crypto.randomBytes(20).toString("hex");
  user.resetExpires = Date.now() + 3600000;
  await user.save();
  res.json({
    message:
      "Password reset token generated. Configure email delivery before production.",
    resetToken: user.resetToken,
  });
});
app.post("/api/auth/reset-password", async (req, res) => {
  const user = await User.findOne({
    resetToken: req.body.token,
    resetExpires: { $gt: Date.now() },
  });
  if (!user)
    return res.status(400).json({ message: "Invalid or expired reset link" });
  user.password = await bcrypt.hash(req.body.password, 12);
  user.resetToken = undefined;
  user.resetExpires = undefined;
  await user.save();
  res.json({ message: "Password updated. You can now sign in." });
});
app.get("/api/auth/me", auth(), (req, res) => res.json(req.user));

app.get("/api/dashboard", auth(), async (req, res) => {
  const tx = await Transaction.find()
    .populate("party", "name")
    .sort("-transactionDate");
  const received = tx
    .filter((t) => t.direction === "received")
    .reduce((s, t) => s + t.amount, 0);
  const transferred = tx
    .filter((t) => t.direction === "transferred")
    .reduce((s, t) => s + t.amount, 0);
  res.json({
    received,
    transferred,
    balance: received - transferred,
    transactions: tx.slice(0, 6),
    activeParties: await Party.countDocuments({ active: true }),
  });
});

app.get("/api/test", async (req, res) =>
  res.json({ message: "ok", server: "Vercel" }),
);

app.get("/api/parties", auth(), async (req, res) =>
  res.json(await Party.find().sort("-createdAt")),
);
app.post("/api/parties", auth("admin", "operator"), async (req, res) =>
  res.status(201).json(await Party.create(req.body)),
);
app.put("/api/parties/:id", auth("admin", "operator"), async (req, res) =>
  res.json(
    await Party.findByIdAndUpdate(req.params.id, req.body, { new: true }),
  ),
);
app.patch(
  "/api/parties/:id/status",
  auth("admin", "operator"),
  async (req, res) =>
    res.json(
      await Party.findByIdAndUpdate(
        req.params.id,
        { active: req.body.active },
        { new: true },
      ),
    ),
);
app.get("/api/transactions", auth(), async (req, res) =>
  res.json(
    await Transaction.find()
      .populate("party", "name type")
      .populate("createdBy", "name")
      .sort("-transactionDate"),
  ),
);
app.post(
  "/api/transactions",
  auth("admin", "operator", "accounts"),
  upload.single("attachment"),
  async (req, res) => {
    const data = {
      ...req.body,
      amount: Number(req.body.amount),
      createdBy: req.user._id,
      attachment: req.file ? `/uploads/${req.file.filename}` : undefined,
    };
    res.status(201).json(await Transaction.create(data));
  },
);
app.get("/api/users", auth("admin"), async (req, res) =>
  res.json(await User.find().select("-password -resetToken")),
);
app.post("/api/users", auth("admin"), async (req, res) => {
  const password = await bcrypt.hash(req.body.password, 12);
  res.status(201).json(await User.create({ ...req.body, password }));
});

async function seed() {
  if (await User.countDocuments()) return;
  await User.create({
    name: "Admin User",
    email: "admin@finflow.test",
    password: await bcrypt.hash("Admin@123", 12),
    role: "admin",
  });
  await Party.create([
    {
      name: "Acme Retail Ltd.",
      type: "Customer",
      email: "finance@acme.test",
      active: true,
    },
    {
      name: "Zenith Supplies",
      type: "Vendor",
      phone: "+91 98765 43210",
      active: true,
    },
  ]);
  // console.log("Seeded: admin@finflow.test / Admin@123");
}
mongoose
  .connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log(process.env.MONGODB_URI);

    await seed();
    app.listen(process.env.PORT || 5000, () =>
      console.log("API running on port 5000"),
    );
  })
  .catch((e) => console.error("MongoDB connection failed:", e.message));
