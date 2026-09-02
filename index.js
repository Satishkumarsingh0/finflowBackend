import dotenv from "dotenv";
import path from "path";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import crypto from "crypto";

const environment = process.env.NODE_ENV || "local";
dotenv.config({ path: path.resolve(process.cwd(), `.env.${environment}`) });
dotenv.config({ path: path.resolve(process.cwd(), ".env") });

const app = express();

const roles = ["admin", "operator", "accounts"];
const allowedOrigins = (process.env.CLIENT_URL || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

const isAllowedOrigin = (origin) =>
  !origin ||
  allowedOrigins.includes(origin) ||
  /^https:\/\/finflow-[a-z0-9-]+\.vercel\.app$/.test(origin) ||
  /^http:\/\/localhost:(5173|5174)$/.test(origin);

const corsOptions = {
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS origin not allowed: ${origin}`));
    }
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));

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
    folder: "finflow/transactions",
    resource_type: "auto",
  },
});

const isAcceptedAttachment = (file) =>
  file.mimetype === "application/pdf" || file.mimetype.startsWith("image/");
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, callback) => {
    if (isAcceptedAttachment(file)) return callback(null, true);
    callback(new Error("Only image files and PDF documents are allowed."));
  },
});
const uploadAttachment = (req, res, next) =>
  upload.single("attachment")(req, res, (error) => {
    if (!error) return next();
    const message = error.code === "LIMIT_FILE_SIZE"
      ? "Attachment must be 5 MB or smaller."
      : error.message || "Could not process the attachment.";
    return res.status(400).json({ message });
  });

/* ---------------- SCHEMAS ---------------- */

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: roles, default: "operator" },
    resetToken: String,
    resetExpires: Date,
  },
  { timestamps: true },
);

const partySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
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
    amount: { type: Number, required: true, min: 0 },
    currency: { type: String, default: "INR" },
    mode: {
      type: String,
      enum: ["Bank Transfer", "Cash", "Cheque", "UPI", "Card"],
    },
    party: { type: mongoose.Schema.Types.ObjectId, ref: "Party" },
    reference: String,
    notes: String,

    attachment: String,
    attachmentPublicId: String,
    attachmentOriginalName: String,

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
  const user = await User.findOne({ email: req.body.email?.toLowerCase() });

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
  try {
    res.status(201).json(await Party.create(req.body));
  } catch (error) {
    res.status(400).json({ message: error.message || "Could not create party." });
  }
});

app.put("/api/parties/:id", auth("admin", "operator"), async (req, res) => {
  try {
    const party = await Party.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!party) return res.status(404).json({ message: "Party not found." });
    res.json(party);
  } catch (error) {
    res.status(400).json({ message: error.message || "Could not update party." });
  }
});

app.patch("/api/parties/:id/status", auth("admin", "operator"), async (req, res) => {
  if (typeof req.body.active !== "boolean") {
    return res.status(400).json({ message: "Active status must be true or false." });
  }
  const party = await Party.findByIdAndUpdate(
    req.params.id,
    { active: req.body.active },
    { new: true },
  );
  if (!party) return res.status(404).json({ message: "Party not found." });
  res.json(party);
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
  uploadAttachment,
  async (req, res) => {
    try {
      if (!Number.isFinite(Number(req.body.amount)) || Number(req.body.amount) <= 0) {
        return res.status(400).json({ message: "Amount must be greater than zero." });
      }
      const transaction = await Transaction.create({
        ...req.body,
        amount: Number(req.body.amount),
        createdBy: req.user._id,
        attachment: req.file?.path || null,
        attachmentPublicId: req.file?.filename || null,
        attachmentOriginalName: req.file?.originalname || null,
      });
      res.status(201).json(transaction);
    } catch (error) {
      console.error("Transaction attachment upload failed:", error.message);
      res.status(502).json({
        message: "Could not upload the attachment. Please try again.",
      });
    }
  },
);

/* ---------------- USERS ---------------- */

app.get("/api/users", auth("admin"), async (req, res) => {
  res.json(await User.find().select("-password -resetToken"));
});

app.post("/api/users", auth("admin"), async (req, res) => {
  try {
    if (!req.body.password || req.body.password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }
    const password = await bcrypt.hash(req.body.password, 12);
    const user = await User.create({ ...req.body, password });
    res.status(201).json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    const message = error.code === 11000
      ? "A user with this email already exists."
      : error.message || "Could not create user.";
    res.status(400).json({ message });
  }
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

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected");
    await seed();
    if (!process.env.VERCEL) {
      const port = Number(process.env.PORT || 5000);
      app.listen(port, () => console.log(`API running on http://localhost:${port} (${environment})`));
    }
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exitCode = 1;
  }
}

startServer();

export default app;
