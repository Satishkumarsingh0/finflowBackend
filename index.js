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

dotenv.config({
  path: path.resolve(process.cwd(), `.env.${environment}`),
});

dotenv.config({
  path: path.resolve(process.cwd(), ".env"),
});

const app = express();

const roles = ["admin", "operator", "accounts"];

const allowedOrigins = (process.env.CLIENT_URL || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

const isAllowedOrigin = (origin) => {
  if (!origin) return true;

  if (allowedOrigins.includes(origin)) {
    return true;
  }

  if (/^https:\/\/finflow-[a-z0-9-]+\.vercel\.app$/.test(origin)) {
    return true;
  }

  if (/^http:\/\/localhost:(5173|5174)$/.test(origin)) {
    return true;
  }

  return false;
};

const corsOptions = {
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      return callback(null, true);
    }

    return callback(new Error(`CORS origin not allowed: ${origin}`));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "1mb" }));

/* ---------------- DATABASE ---------------- */

let databasePromise = null;
let seedPromise = null;

const connectDatabase = async () => {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is not configured.");
  }

  if (!databasePromise) {
    databasePromise = mongoose
      .connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 10000,
        connectTimeoutMS: 10000,
        maxPoolSize: 10,
      })
      .catch((error) => {
        databasePromise = null;
        throw error;
      });
  }

  await databasePromise;
  return mongoose.connection;
};

const ensureDatabase = async (req, res, next) => {
  try {
    await connectDatabase();
    next();
  } catch (error) {
    console.error("Database connection failed:", error.message);

    res.status(503).json({
      message: "Database service is temporarily unavailable.",
    });
  }
};

/* ---------------- HEALTH CHECK ---------------- */

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
  file.mimetype === "application/pdf" ||
  file.mimetype.startsWith("image/");

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (req, file, callback) => {
    if (isAcceptedAttachment(file)) {
      return callback(null, true);
    }

    return callback(
      new Error("Only image files and PDF documents are allowed."),
    );
  },
});

const uploadAttachment = (req, res, next) => {
  upload.single("attachment")(req, res, (error) => {
    if (!error) {
      return next();
    }

    const message =
      error.code === "LIMIT_FILE_SIZE"
        ? "Attachment must be 5 MB or smaller."
        : error.message || "Could not process the attachment.";

    return res.status(400).json({ message });
  });
};

/* ---------------- SCHEMAS ---------------- */

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: roles,
      default: "operator",
    },
    resetToken: String,
    resetExpires: Date,
  },
  {
    timestamps: true,
  },
);

const partySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    type: {
      type: String,
      enum: ["Customer", "Vendor", "Other"],
      default: "Customer",
    },
    phone: String,
    email: String,
    taxId: String,
    address: String,
    active: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  },
);

const transactionSchema = new mongoose.Schema(
  {
    direction: {
      type: String,
      enum: ["received", "transferred"],
      required: true,
    },
    amount: {
      type: Number,
      required: true,
      min: 0,
    },
    currency: {
      type: String,
      default: "INR",
    },
    mode: {
      type: String,
      enum: ["Bank Transfer", "Cash", "Cheque", "UPI", "Card"],
      required: true,
    },
    party: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Party",
    },
    reference: String,
    notes: String,
    attachment: String,
    attachmentPublicId: String,
    attachmentOriginalName: String,
    transactionDate: {
      type: Date,
      default: Date.now,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  {
    timestamps: true,
  },
);

const User = mongoose.models.User || mongoose.model("User", userSchema);
const Party = mongoose.models.Party || mongoose.model("Party", partySchema);
const Transaction =
  mongoose.models.Transaction ||
  mongoose.model("Transaction", transactionSchema);

/* ---------------- SEED ---------------- */

const seedAdmin = async () => {
  if (!seedPromise) {
    seedPromise = User.countDocuments()
      .then(async (count) => {
        if (count > 0) {
          return;
        }

        if (!process.env.SEED_ADMIN_PASSWORD) {
          console.warn(
            "SEED_ADMIN_PASSWORD is not configured. Admin user was not created.",
          );
          return;
        }

        await User.create({
          name: "Admin User",
          email: "admin@finflow.test",
          password: await bcrypt.hash(process.env.SEED_ADMIN_PASSWORD, 12),
          role: "admin",
        });
      })
      .catch((error) => {
        seedPromise = null;
        throw error;
      });
  }

  await seedPromise;
};

/* ---------------- AUTH ---------------- */

const sign = (user) => {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured.");
  }

  return jwt.sign(
    {
      id: user._id,
      role: user.role,
      name: user.name,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "8h",
    },
  );
};

const auth =
  (...allowed) =>
  async (req, res, next) => {
    try {
      const authorization = req.headers.authorization || "";
      const token = authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : null;

      if (!token) {
        return res.status(401).json({
          message: "Authentication token is required.",
        });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.user = await User.findById(decoded.id).select("-password");

      if (!req.user) {
        return res.status(401).json({
          message: "Unauthorized.",
        });
      }

      if (allowed.length && !allowed.includes(req.user.role)) {
        return res.status(403).json({
          message: "Access denied.",
        });
      }

      next();
    } catch (error) {
      return res.status(401).json({
        message: "Please sign in again.",
      });
    }
  };

/* ---------------- DATABASE MIDDLEWARE ---------------- */

app.use("/api", ensureDatabase);

/* ---------------- AUTH ROUTES ---------------- */

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();
    const password = req.body?.password;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Invalid credentials.",
      });
    }

    return res.json({
      token: sign(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Login failed:", error.message);

    return res.status(500).json({
      message: "Login failed. Please try again.",
    });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();
    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        message: "If the account exists, reset instructions have been generated.",
      });
    }

    user.resetToken = crypto.randomBytes(20).toString("hex");
    user.resetExpires = Date.now() + 60 * 60 * 1000;

    await user.save();

    return res.json({
      message: "Reset token generated.",
      token: user.resetToken,
    });
  } catch (error) {
    console.error("Forgot password failed:", error.message);

    return res.status(500).json({
      message: "Could not process the password reset request.",
    });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body || {};

    if (!token || !password || password.length < 6) {
      return res.status(400).json({
        message: "A valid token and password of at least 6 characters are required.",
      });
    }

    const user = await User.findOne({
      resetToken: token,
      resetExpires: {
        $gt: Date.now(),
      },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired token.",
      });
    }

    user.password = await bcrypt.hash(password, 12);
    user.resetToken = undefined;
    user.resetExpires = undefined;

    await user.save();

    return res.json({
      message: "Password updated.",
    });
  } catch (error) {
    console.error("Reset password failed:", error.message);

    return res.status(500).json({
      message: "Could not reset the password.",
    });
  }
});

app.get("/api/auth/me", auth(), (req, res) => {
  res.json(req.user);
});

/* ---------------- DASHBOARD ---------------- */

app.get("/api/dashboard", auth(), async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate("party", "name")
      .sort("-transactionDate");

    const received = transactions
      .filter((transaction) => transaction.direction === "received")
      .reduce((total, transaction) => total + transaction.amount, 0);

    const transferred = transactions
      .filter((transaction) => transaction.direction === "transferred")
      .reduce((total, transaction) => total + transaction.amount, 0);

    return res.json({
      received,
      transferred,
      balance: received - transferred,
      transactions: transactions.slice(0, 6),
      activeParties: await Party.countDocuments({ active: true }),
    });
  } catch (error) {
    console.error("Dashboard request failed:", error.message);

    return res.status(500).json({
      message: "Could not load dashboard data.",
    });
  }
});

/* ---------------- PARTIES ---------------- */

app.get("/api/parties", auth(), async (req, res) => {
  try {
    const parties = await Party.find().sort("-createdAt");
    res.json(parties);
  } catch (error) {
    console.error("Get parties failed:", error.message);
    res.status(500).json({ message: "Could not load parties." });
  }
});

app.post("/api/parties", auth("admin", "operator"), async (req, res) => {
  try {
    const party = await Party.create(req.body);
    res.status(201).json(party);
  } catch (error) {
    console.error("Create party failed:", error.message);
    res.status(400).json({
      message: error.message || "Could not create party.",
    });
  }
});

app.put("/api/parties/:id", auth("admin", "operator"), async (req, res) => {
  try {
    const party = await Party.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!party) {
      return res.status(404).json({
        message: "Party not found.",
      });
    }

    return res.json(party);
  } catch (error) {
    console.error("Update party failed:", error.message);
    return res.status(400).json({
      message: error.message || "Could not update party.",
    });
  }
});

app.patch(
  "/api/parties/:id/status",
  auth("admin", "operator"),
  async (req, res) => {
    try {
      if (typeof req.body.active !== "boolean") {
        return res.status(400).json({
          message: "Active status must be true or false.",
        });
      }

      const party = await Party.findByIdAndUpdate(
        req.params.id,
        { active: req.body.active },
        { new: true, runValidators: true },
      );

      if (!party) {
        return res.status(404).json({
          message: "Party not found.",
        });
      }

      return res.json(party);
    } catch (error) {
      console.error("Update party status failed:", error.message);
      return res.status(400).json({
        message: error.message || "Could not update party status.",
      });
    }
  },
);

/* ---------------- TRANSACTIONS ---------------- */

app.get("/api/transactions", auth(), async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate("party", "name type")
      .populate("createdBy", "name")
      .sort("-transactionDate");

    res.json(transactions);
  } catch (error) {
    console.error("Get transactions failed:", error.message);
    res.status(500).json({
      message: "Could not load transactions.",
    });
  }
});

app.post(
  "/api/transactions",
  auth("admin", "operator", "accounts"),
  uploadAttachment,
  async (req, res) => {
    try {
      const amount = Number(req.body.amount);

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          message: "Amount must be greater than zero.",
        });
      }

      const transaction = await Transaction.create({
        ...req.body,
        amount,
        createdBy: req.user._id,
        attachment: req.file?.path || null,
        attachmentPublicId: req.file?.filename || null,
        attachmentOriginalName: req.file?.originalname || null,
      });

      return res.status(201).json(transaction);
    } catch (error) {
      console.error("Create transaction failed:", error.message);

      return res.status(502).json({
        message: "Could not save the transaction or upload the attachment.",
      });
    }
  },
);

/* ---------------- USERS ---------------- */

app.get("/api/users", auth("admin"), async (req, res) => {
  try {
    const users = await User.find().select("-password -resetToken");
    res.json(users);
  } catch (error) {
    console.error("Get users failed:", error.message);
    res.status(500).json({
      message: "Could not load users.",
    });
  }
});

app.post("/api/users", auth("admin"), async (req, res) => {
  try {
    const { password } = req.body || {};

    if (!password || password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      ...req.body,
      password: hashedPassword,
    });

    return res.status(201).json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    const message =
      error.code === 11000
        ? "A user with this email already exists."
        : error.message || "Could not create user.";

    return res.status(400).json({ message });
  }
});

/* ---------------- ERROR HANDLER ---------------- */

app.use((error, req, res, next) => {
  console.error("Unhandled API error:", error);

  if (res.headersSent) {
    return next(error);
  }

  if (error instanceof SyntaxError && error.status === 400) {
    return res.status(400).json({
      message: "Invalid JSON request body.",
    });
  }

  return res.status(500).json({
    message: "Internal server error.",
  });
});

/* ---------------- LOCAL SERVER ---------------- */

const startLocalServer = async () => {
  try {
    await connectDatabase();
    await seedAdmin();

    const port = Number(process.env.PORT || 5000);

    app.listen(port, () => {
      console.log(
        `API running on http://localhost:${port} (${environment})`,
      );
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exitCode = 1;
  }
};

if (!process.env.VERCEL) {
  startLocalServer();
}

export default app;