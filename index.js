import "dotenv/config";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import crypto from "crypto";

const app = express();

const roles = ["admin", "operator", "accounts"];

app.use(cors({ origin: process.env.CLIENT_URL }));
app.use(express.json());

app.get("/", (req, res) => {
  res.json({ status: "API is running" });
});

/* ---------------- CLOUDINARY ---------------- */

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "finflow",
    resource_type: "auto",
    allowed_formats: ["jpg", "jpeg", "png", "pdf", "doc", "docx"],
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

/* ---------------- SCHEMAS ---------------- */

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, enum: roles, default: "operator" },
    resetToken: String,
    resetExpires: Date,
  },
  { timestamps: true },
);

const partySchema = new mongoose.Schema(
  {
    name: String,
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
    },
    amount: Number,
    currency: { type: String, default: "INR" },
    mode: {
      type: String,
      enum: ["Bank Transfer", "Cash", "Cheque", "UPI", "Card"],
    },
    party: { type: mongoose.Schema.Types.ObjectId, ref: "Party" },
    reference: String,
    notes: String,

    // Cloudinary URL
    attachment: String,

    transactionDate: { type: Date, default: Date.now },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true },
);

const User = mongoose.model("User", userSchema);
const Party = mongoose.model("Party", partySchema);
const Transaction = mongoose.model("Transaction", transactionSchema);

/* ---------------- AUTH ---------------- */

const sign = (user) =>
  jwt.sign(
    { id: user._id, role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "8h" },
  );

const auth =
  (...allowed) =>
  async (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.user = await User.findById(decoded.id).select("-password");

      if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      if (allowed.length && !allowed.includes(req.user.role)) {
        return res.status(403).json({ message: "Access denied" });
      }

      next();
    } catch {
      res.status(401).json({ message: "Please sign in again" });
    }
  };

/* ---------------- AUTH ROUTES ---------------- */

app.post("/api/auth/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  res.json({
    token: sign(user),
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});

app.post("/api/auth/forgot-password", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return res.json({
      message: "If account exists, reset token created.",
    });
  }

  user.resetToken = crypto.randomBytes(20).toString("hex");
  user.resetExpires = Date.now() + 3600000;

  await user.save();

  res.json({
    message: "Reset token generated",
    token: user.resetToken,
  });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const user = await User.findOne({
    resetToken: req.body.token,
    resetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({ message: "Invalid token" });
  }

  user.password = await bcrypt.hash(req.body.password, 12);
  user.resetToken = undefined;
  user.resetExpires = undefined;

  await user.save();

  res.json({ message: "Password updated" });
});

app.get("/api/auth/me", auth(), (req, res) => res.json(req.user));

/* ---------------- DASHBOARD ---------------- */

app.get("/api/dashboard", auth(), async (req, res) => {
  const tx = await Transaction.find()
    .populate("party", "name")
    .sort("-transactionDate");

  const received = tx
    .filter((t) => t.direction === "received")
    .reduce((a, b) => a + b.amount, 0);

  const transferred = tx
    .filter((t) => t.direction === "transferred")
    .reduce((a, b) => a + b.amount, 0);

  res.json({
    received,
    transferred,
    balance: received - transferred,
    transactions: tx.slice(0, 6),
    activeParties: await Party.countDocuments({ active: true }),
  });
});

/* ---------------- PARTIES ---------------- */

app.get("/api/parties", auth(), async (req, res) => {
  res.json(await Party.find().sort("-createdAt"));
});

app.post("/api/parties", auth("admin", "operator"), async (req, res) => {
  res.status(201).json(await Party.create(req.body));
});

app.put("/api/parties/:id", auth("admin", "operator"), async (req, res) => {
  res.json(
    await Party.findByIdAndUpdate(req.params.id, req.body, { new: true }),
  );
});

/* ---------------- TRANSACTIONS ---------------- */

app.get("/api/transactions", auth(), async (req, res) => {
  res.json(
    await Transaction.find()
      .populate("party", "name type")
      .populate("createdBy", "name")
      .sort("-transactionDate"),
  );
});

app.post(
  "/api/transactions",
  auth("admin", "operator", "accounts"),
  upload.single("attachment"),
  async (req, res) => {
    const transaction = await Transaction.create({
      ...req.body,
      amount: Number(req.body.amount),
      createdBy: req.user._id,

      // Cloudinary file URL
      attachment: req.file ? req.file.path : null,
    });

    res.status(201).json(transaction);
  },
);

/* ---------------- USERS ---------------- */

app.get("/api/users", auth("admin"), async (req, res) => {
  res.json(await User.find().select("-password -resetToken"));
});

app.post("/api/users", auth("admin"), async (req, res) => {
  const password = await bcrypt.hash(req.body.password, 12);

  res.status(201).json(await User.create({ ...req.body, password }));
});

/* ---------------- SEED ---------------- */

async function seed() {
  if (await User.countDocuments()) return;

  await User.create({
    name: "Admin User",
    email: "admin@finflow.test",
    password: await bcrypt.hash("Admin@123", 12),
    role: "admin",
  });
}

/* ---------------- DB ---------------- */

mongoose
  .connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("MongoDB connected");
    await seed();
  })
  .catch((err) => console.error(err));

export default app;
