import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cloudbase from "@cloudbase/node-sdk";
import { z } from "zod";

const required = [
  "CLOUDBASE_ENV_ID",
  "JWT_SECRET",
  "PII_ENCRYPTION_KEY",
  "PII_HASH_SECRET",
  "BOOTSTRAP_TOKEN",
];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
}

if (!/^[a-fA-F0-9]{64}$/.test(process.env.PII_ENCRYPTION_KEY)) {
  throw new Error("PII_ENCRYPTION_KEY must be exactly 64 hexadecimal characters");
}

if (process.env.JWT_SECRET.length < 32 || process.env.PII_HASH_SECRET.length < 32) {
  throw new Error("JWT_SECRET and PII_HASH_SECRET must contain at least 32 characters");
}

const app = express();
const cloud = cloudbase.init({ env: process.env.CLOUDBASE_ENV_ID });
const db = cloud.database();

const collections = {
  activities: db.collection("activities"),
  registrations: db.collection("registrations"),
  admins: db.collection("admins"),
  audit: db.collection("audit_logs"),
};

const config = {
  port: Number(process.env.PORT || 8080),
  origins: (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim().replace(/\/$/, ""))
    .filter(Boolean),
  jwtSecret: process.env.JWT_SECRET,
  piiKey: Buffer.from(process.env.PII_ENCRYPTION_KEY, "hex"),
  hashSecret: process.env.PII_HASH_SECRET,
  bootstrapToken: process.env.BOOTSTRAP_TOKEN,
  tokenExpiresIn: process.env.TOKEN_EXPIRES_IN || "8h",
  consentVersion: process.env.CONSENT_VERSION || "2026-01",
};

app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || config.origins.includes(origin.replace(/\/$/, ""))) {
        callback(null, true);
        return;
      }
      callback(new Error("Origin not allowed"));
    },
    methods: ["GET", "POST", "PATCH", "PUT", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Request-ID"],
    maxAge: 86400,
  }),
);
app.use(express.json({ limit: "100kb" }));

const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 80,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "RATE_LIMITED", message: "提交过于频繁，请稍后再试。" },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "RATE_LIMITED", message: "登录尝试过多，请稍后再试。" },
});

app.use("/api", publicLimiter);

const registrationSchema = z.object({
  activityId: z.string().min(3).max(128),
  requestId: z.string().uuid(),
  name: z.string().trim().min(2).max(40),
  phone: z.string().trim().regex(/^(\+?86)?1[3-9]\d{9}$/),
  email: z.string().trim().email().max(160),
  birthYear: z.coerce.number().int().min(1940).max(new Date().getFullYear() - 16),
  experience: z.string().trim().max(800).default(""),
  consent: z.literal(true),
  website: z.string().max(0).optional().default(""),
});

const loginSchema = z.object({
  email: z.string().trim().email().max(160),
  password: z.string().min(10).max(128),
});

const bootstrapSchema = loginSchema.extend({
  name: z.string().trim().min(2).max(40),
  bootstrapToken: z.string().min(16).max(256),
});

const createAdminSchema = loginSchema.extend({
  name: z.string().trim().min(2).max(40),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(10).max(128),
  newPassword: z.string().min(12).max(128),
});

const manageAdminSchema = z
  .object({
    active: z.boolean().optional(),
    password: z.string().min(12).max(128).optional(),
  })
  .refine((value) => value.active !== undefined || value.password !== undefined, {
    message: "至少提交一项管理员变更。",
  });

const updateRegistrationSchema = z.object({
  status: z.enum(["pending", "approved", "waitlisted", "rejected", "cancelled"]),
  adminNote: z.string().trim().max(1000).default(""),
});

const activitySchema = z.object({
  title: z.string().trim().min(2).max(80),
  titleEn: z.string().trim().min(2).max(120),
  category: z.string().trim().min(2).max(40),
  categoryEn: z.string().trim().min(2).max(60),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  day: z.string().regex(/^\d{2}$/),
  month: z.string().regex(/^[A-Z]{3}$/),
  year: z.string().regex(/^\d{4}$/),
  time: z.string().trim().min(3).max(40),
  district: z.string().trim().min(2).max(40),
  location: z.string().trim().min(2).max(120),
  capacity: z.coerce.number().int().min(1).max(100000),
  serviceHours: z.coerce.number().min(0.5).max(24),
  description: z.string().trim().min(10).max(2000),
  requirements: z.array(z.string().trim().min(1).max(200)).min(1).max(12),
  published: z.boolean(),
  registrationOpen: z.boolean(),
  sortOrder: z.coerce.number().int().min(0).max(9999).default(100),
});

function parse(schema, value) {
  const result = schema.safeParse(value);
  if (!result.success) {
    const error = new Error("提交信息不完整或格式不正确。");
    error.status = 400;
    error.code = "VALIDATION_ERROR";
    error.details = result.error.issues.map(({ path, message }) => ({
      field: path.join("."),
      message,
    }));
    throw error;
  }
  return result.data;
}

function normalizeEmail(value) {
  return value.trim().toLowerCase();
}

function normalizePhone(value) {
  const digits = value.replace(/\D/g, "");
  return digits.startsWith("86") && digits.length === 13 ? digits.slice(2) : digits;
}

function stableHash(value) {
  return crypto.createHmac("sha256", config.hashSecret).update(value).digest("hex");
}

function safeEqual(left, right) {
  const leftDigest = crypto.createHash("sha256").update(String(left)).digest();
  const rightDigest = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}

function firstRecord(result) {
  if (Array.isArray(result?.data)) return result.data[0];
  return result?.data || null;
}

function encryptPii(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", config.piiKey, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    version: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: encrypted.toString("base64"),
  };
}

function decryptPii(value) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    config.piiKey,
    Buffer.from(value.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(value.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(value.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString("utf8"));
}

function now() {
  return new Date().toISOString();
}

function referenceCode() {
  const date = new Date();
  const stamp = `${date.getFullYear()}${String(date.getMonth() + 1).padStart(2, "0")}${String(date.getDate()).padStart(2, "0")}`;
  return `CIVIC-${stamp}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
}

function publicActivity(record) {
  const remaining = Math.max(0, Number(record.capacity) - Number(record.registeredCount || 0));
  return {
    id: record._id,
    title: record.title,
    titleEn: record.titleEn,
    category: record.category,
    categoryEn: record.categoryEn,
    date: record.date,
    day: record.day,
    month: record.month,
    year: record.year,
    time: record.time,
    district: record.district,
    location: record.location,
    capacity: record.capacity,
    registeredCount: record.registeredCount || 0,
    remaining,
    serviceHours: record.serviceHours,
    description: record.description,
    requirements: record.requirements,
    registrationOpen: Boolean(record.registrationOpen && remaining > 0),
  };
}

async function audit(action, admin, payload = {}) {
  try {
    await collections.audit.add({
      action,
      adminId: admin?.id || null,
      adminEmail: admin?.email || null,
      payload,
      createdAt: now(),
    });
  } catch (error) {
    console.error("Audit log write failed", { action, message: error.message });
  }
}

function signAdmin(admin) {
  return jwt.sign(
    { sub: admin._id, email: admin.email, name: admin.name, role: "admin" },
    config.jwtSecret,
    { expiresIn: config.tokenExpiresIn, issuer: "civic-volunteer-api", audience: "civic-admin" },
  );
}

async function requireAdmin(req, res, next) {
  try {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
    if (!token) {
      return res.status(401).json({ error: "AUTH_REQUIRED", message: "请登录管理后台。" });
    }
    const decoded = jwt.verify(token, config.jwtSecret, {
      issuer: "civic-volunteer-api",
      audience: "civic-admin",
    });
    const result = await collections.admins.doc(decoded.sub).get();
    const admin = firstRecord(result);
    if (!admin?.active) {
      return res.status(403).json({ error: "ACCOUNT_DISABLED", message: "管理员账号已停用。" });
    }
    req.admin = {
      id: admin._id,
      email: admin.email,
      name: admin.name,
      mustChangePassword: Boolean(admin.mustChangePassword),
    };
    if (
      req.admin.mustChangePassword &&
      !["/api/admin/change-password", "/api/admin/me"].includes(req.originalUrl.split("?")[0])
    ) {
      return res.status(403).json({
        error: "PASSWORD_CHANGE_REQUIRED",
        message: "首次登录必须先修改密码。",
      });
    }
    next();
  } catch {
    res.status(401).json({ error: "INVALID_TOKEN", message: "登录已失效，请重新登录。" });
  }
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "civic-volunteer-api", time: now() });
});

app.get("/api/activities", async (_req, res, next) => {
  try {
    const result = await collections.activities
      .where({ published: true })
      .orderBy("sortOrder", "asc")
      .limit(100)
      .get();
    res.json({ activities: result.data.map(publicActivity) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/registrations", registrationLimiter, async (req, res, next) => {
  try {
    const input = parse(registrationSchema, req.body);
    const phone = normalizePhone(input.phone);
    const email = normalizeEmail(input.email);
    const phoneHash = stableHash(phone);
    const registrationId = stableHash(`registration:${input.activityId}:${phone}`).slice(0, 48);
    const reference = referenceCode();
    const createdAt = now();
    const sourceIp = req.ip || "";
    const result = await db.runTransaction(async (transaction) => {
      const registrations = transaction.collection("registrations");
      const activityCollection = transaction.collection("activities");
      const existing = firstRecord(await registrations.doc(registrationId).get());
      if (existing) {
        if (existing.requestId === input.requestId) {
          return { reference: existing.reference, status: existing.status, duplicate: true };
        }
        const error = new Error("该手机号已有本活动的报名记录；如需恢复已取消报名，请联系管理员。");
        error.status = 409;
        error.code = "ALREADY_REGISTERED";
        throw error;
      }

      const activity = firstRecord(await activityCollection.doc(input.activityId).get());
      if (!activity?.published || !activity?.registrationOpen) {
        const error = new Error("该活动暂未开放报名。");
        error.status = 409;
        error.code = "REGISTRATION_CLOSED";
        throw error;
      }
      if (Number(activity.registeredCount || 0) >= Number(activity.capacity)) {
        const error = new Error("该活动名额已满。");
        error.status = 409;
        error.code = "ACTIVITY_FULL";
        throw error;
      }

      await activityCollection.doc(input.activityId).update({
        registeredCount: Number(activity.registeredCount || 0) + 1,
        updatedAt: createdAt,
      });
      await registrations.doc(registrationId).set({
        activityId: input.activityId,
        activityTitle: activity.title,
        requestId: input.requestId,
        reference,
        status: "pending",
        pii: encryptPii({
          name: input.name,
          phone,
          email,
          birthYear: input.birthYear,
          experience: input.experience,
        }),
        phoneHash,
        emailHash: stableHash(email),
        consentVersion: config.consentVersion,
        consentAt: createdAt,
        sourceIpHash: stableHash(sourceIp),
        userAgent: String(req.headers["user-agent"] || "").slice(0, 240),
        adminNote: "",
        createdAt,
        updatedAt: createdAt,
      });
      return { reference, status: "pending", duplicate: false };
    });

    res.status(result.duplicate ? 200 : 201).json(result);
  } catch (error) {
    next(error);
  }
});

app.get("/api/registrations/status", registrationLimiter, async (req, res, next) => {
  try {
    const reference = String(req.query.reference || "").trim().toUpperCase();
    const phone = normalizePhone(String(req.query.phone || ""));
    if (!/^CIVIC-\d{8}-[A-F0-9]{8}$/.test(reference) || !/^1[3-9]\d{9}$/.test(phone)) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: "报名编号或手机号格式不正确。" });
    }
    const result = await collections.registrations
      .where({ reference, phoneHash: stableHash(phone) })
      .limit(1)
      .get();
    const registration = result.data?.[0];
    if (!registration) {
      return res.status(404).json({ error: "NOT_FOUND", message: "未找到匹配的报名记录。" });
    }
    const activityResult = await collections.activities.doc(registration.activityId).get();
    const activity = firstRecord(activityResult);
    res.json({
      registration: {
        reference: registration.reference,
        status: registration.status,
        activityTitle: registration.activityTitle,
        activityTitleEn: activity?.titleEn || "",
        date: activity?.date || "",
        time: activity?.time || "",
        location: activity?.location || "",
        updatedAt: registration.updatedAt,
      },
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/bootstrap", loginLimiter, async (req, res, next) => {
  try {
    const input = parse(bootstrapSchema, req.body);
    if (!safeEqual(input.bootstrapToken, config.bootstrapToken)) {
      return res.status(403).json({ error: "INVALID_BOOTSTRAP_TOKEN", message: "初始化口令无效。" });
    }
    const existing = await collections.admins.limit(1).get();
    if (existing.data.length) {
      return res.status(409).json({ error: "ALREADY_INITIALIZED", message: "管理员已经初始化。" });
    }
    const email = normalizeEmail(input.email);
    const createdAt = now();
    const result = await collections.admins.add({
      email,
      name: input.name,
      passwordHash: await bcrypt.hash(input.password, 12),
      active: true,
      mustChangePassword: false,
      createdAt,
      updatedAt: createdAt,
      lastLoginAt: null,
    });
    const admin = { _id: result.id, email, name: input.name };
    await audit("admin.bootstrap", { id: result.id, email, name: input.name });
    res.status(201).json({
      token: signAdmin(admin),
      admin: { email, name: input.name, mustChangePassword: false },
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/login", loginLimiter, async (req, res, next) => {
  try {
    const input = parse(loginSchema, req.body);
    const email = normalizeEmail(input.email);
    const result = await collections.admins.where({ email }).limit(1).get();
    const admin = result.data[0];
    if (!admin?.active || !(await bcrypt.compare(input.password, admin.passwordHash))) {
      return res.status(401).json({ error: "INVALID_CREDENTIALS", message: "邮箱或密码不正确。" });
    }
    await collections.admins.doc(admin._id).update({ lastLoginAt: now(), updatedAt: now() });
    await audit("admin.login", { id: admin._id, email: admin.email, name: admin.name });
    res.json({
      token: signAdmin(admin),
      admin: {
        email: admin.email,
        name: admin.name,
        mustChangePassword: Boolean(admin.mustChangePassword),
      },
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/me", requireAdmin, async (req, res) => {
  res.json({ admin: req.admin });
});

app.post("/api/admin/change-password", requireAdmin, async (req, res, next) => {
  try {
    const input = parse(changePasswordSchema, req.body);
    const admin = firstRecord(await collections.admins.doc(req.admin.id).get());
    if (!admin || !(await bcrypt.compare(input.currentPassword, admin.passwordHash))) {
      return res.status(401).json({ error: "INVALID_PASSWORD", message: "当前密码不正确。" });
    }
    if (await bcrypt.compare(input.newPassword, admin.passwordHash)) {
      return res.status(409).json({ error: "PASSWORD_REUSED", message: "新密码不能与当前密码相同。" });
    }
    await collections.admins.doc(req.admin.id).update({
      passwordHash: await bcrypt.hash(input.newPassword, 12),
      mustChangePassword: false,
      updatedAt: now(),
    });
    await audit("admin.password_change", req.admin);
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/registrations", requireAdmin, async (req, res, next) => {
  try {
    const where = {};
    if (req.query.activityId) where.activityId = String(req.query.activityId);
    if (req.query.status && req.query.status !== "all") where.status = String(req.query.status);
    const result = await collections.registrations
      .where(where)
      .orderBy("createdAt", "desc")
      .limit(1000)
      .get();
    const query = String(req.query.q || "").trim().toLowerCase();
    const records = result.data
      .map((record) => ({ ...record, ...decryptPii(record.pii), pii: undefined }))
      .filter((record) => {
        if (!query) return true;
        return [record.name, record.phone, record.email, record.reference, record.activityTitle]
          .some((value) => String(value || "").toLowerCase().includes(query));
      });
    res.json({
      registrations: records,
      total: records.length,
    });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/registrations/:id", requireAdmin, async (req, res, next) => {
  try {
    const input = parse(updateRegistrationSchema, req.body);
    const previousStatus = await db.runTransaction(async (transaction) => {
      const registrationCollection = transaction.collection("registrations");
      const activityCollection = transaction.collection("activities");
      const registration = firstRecord(await registrationCollection.doc(req.params.id).get());
      if (!registration) {
        const error = new Error("报名记录不存在。");
        error.status = 404;
        error.code = "NOT_FOUND";
        throw error;
      }
      const releasing =
        !["cancelled", "rejected"].includes(registration.status) &&
        ["cancelled", "rejected"].includes(input.status);
      const reclaiming =
        ["cancelled", "rejected"].includes(registration.status) &&
        !["cancelled", "rejected"].includes(input.status);

      if (releasing || reclaiming) {
        const activity = firstRecord(await activityCollection.doc(registration.activityId).get());
        if (!activity) {
          const error = new Error("关联活动不存在。");
          error.status = 404;
          error.code = "NOT_FOUND";
          throw error;
        }
        const currentCount = Number(activity.registeredCount || 0);
        if (reclaiming && currentCount >= Number(activity.capacity)) {
          const error = new Error("活动名额已满，无法恢复该报名。");
          error.status = 409;
          error.code = "ACTIVITY_FULL";
          throw error;
        }
        await activityCollection.doc(registration.activityId).update({
          registeredCount: reclaiming ? currentCount + 1 : Math.max(0, currentCount - 1),
          updatedAt: now(),
        });
      }

      await registrationCollection.doc(req.params.id).update({
        status: input.status,
        adminNote: input.adminNote,
        reviewedBy: req.admin.id,
        reviewedAt: now(),
        updatedAt: now(),
      });
      return registration.status;
    });
    await audit("registration.update", req.admin, {
      registrationId: req.params.id,
      from: previousStatus,
      to: input.status,
    });
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/activities", requireAdmin, async (_req, res, next) => {
  try {
    const result = await collections.activities.orderBy("sortOrder", "asc").limit(200).get();
    res.json({ activities: result.data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/activities", requireAdmin, async (req, res, next) => {
  try {
    const input = parse(activitySchema, req.body);
    const createdAt = now();
    const result = await collections.activities.add({
      ...input,
      registeredCount: 0,
      createdAt,
      updatedAt: createdAt,
    });
    await audit("activity.create", req.admin, { activityId: result.id, title: input.title });
    res.status(201).json({ id: result.id });
  } catch (error) {
    next(error);
  }
});

app.put("/api/admin/activities/:id", requireAdmin, async (req, res, next) => {
  try {
    const input = parse(activitySchema, req.body);
    const current = firstRecord(await collections.activities.doc(req.params.id).get());
    if (!current) {
      return res.status(404).json({ error: "NOT_FOUND", message: "活动不存在。" });
    }
    if (input.capacity < Number(current.registeredCount || 0)) {
      return res.status(409).json({
        error: "CAPACITY_TOO_SMALL",
        message: `名额不能少于当前有效报名数 ${current.registeredCount || 0}。`,
      });
    }
    await collections.activities.doc(req.params.id).update({ ...input, updatedAt: now() });
    await audit("activity.update", req.admin, { activityId: req.params.id, title: input.title });
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/admins", requireAdmin, async (_req, res, next) => {
  try {
    const result = await collections.admins.orderBy("createdAt", "asc").limit(100).get();
    res.json({
      admins: result.data.map(({ _id, email, name, active, mustChangePassword, createdAt, lastLoginAt }) => ({
        id: _id,
        email,
        name,
        active,
        mustChangePassword: Boolean(mustChangePassword),
        createdAt,
        lastLoginAt,
      })),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/admins", requireAdmin, async (req, res, next) => {
  try {
    const input = parse(createAdminSchema, req.body);
    const email = normalizeEmail(input.email);
    const duplicate = await collections.admins.where({ email }).limit(1).get();
    if (duplicate.data.length) {
      return res.status(409).json({ error: "ADMIN_EXISTS", message: "该管理员邮箱已存在。" });
    }
    const createdAt = now();
    const result = await collections.admins.add({
      email,
      name: input.name,
      passwordHash: await bcrypt.hash(input.password, 12),
      active: true,
      mustChangePassword: true,
      createdAt,
      updatedAt: createdAt,
      lastLoginAt: null,
    });
    await audit("admin.create", req.admin, { adminId: result.id, email, name: input.name });
    res.status(201).json({ id: result.id });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/admins/:id", requireAdmin, async (req, res, next) => {
  try {
    const input = parse(manageAdminSchema, req.body);
    const target = firstRecord(await collections.admins.doc(req.params.id).get());
    if (!target) {
      return res.status(404).json({ error: "NOT_FOUND", message: "管理员不存在。" });
    }
    if (input.active === false && req.params.id === req.admin.id) {
      return res.status(409).json({ error: "CANNOT_DISABLE_SELF", message: "不能停用当前登录账号。" });
    }
    if (input.active === false) {
      const activeAdmins = await collections.admins.where({ active: true }).count();
      if (Number(activeAdmins.total || 0) <= 1) {
        return res.status(409).json({ error: "LAST_ADMIN", message: "至少需要保留一名正常管理员。" });
      }
    }
    const update = { updatedAt: now() };
    if (input.active !== undefined) update.active = input.active;
    if (input.password) {
      update.passwordHash = await bcrypt.hash(input.password, 12);
      update.mustChangePassword = true;
    }
    await collections.admins.doc(req.params.id).update(update);
    await audit("admin.manage", req.admin, {
      targetAdminId: req.params.id,
      active: input.active,
      passwordReset: Boolean(input.password),
    });
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/export.csv", requireAdmin, async (req, res, next) => {
  try {
    const where = {};
    if (req.query.activityId) where.activityId = String(req.query.activityId);
    if (req.query.status && req.query.status !== "all") where.status = String(req.query.status);
    const result = await collections.registrations
      .where(where)
      .orderBy("createdAt", "desc")
      .limit(1000)
      .get();
    const fields = [
      ["报名编号", "reference"],
      ["活动", "activityTitle"],
      ["姓名", "name"],
      ["手机", "phone"],
      ["邮箱", "email"],
      ["出生年份", "birthYear"],
      ["相关经验", "experience"],
      ["状态", "status"],
      ["报名时间", "createdAt"],
      ["管理员备注", "adminNote"],
    ];
    const escapeCsv = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const lines = [fields.map(([label]) => escapeCsv(label)).join(",")];
    for (const record of result.data) {
      const row = { ...record, ...decryptPii(record.pii) };
      lines.push(fields.map(([, key]) => escapeCsv(row[key])).join(","));
    }
    await audit("registration.export", req.admin, { count: result.data.length });
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="registrations-${Date.now()}.csv"`);
    res.send(`\uFEFF${lines.join("\r\n")}`);
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, _next) => {
  const status = error.status || 500;
  if (status >= 500) {
    console.error("Request failed", {
      message: error.message,
      stack: process.env.NODE_ENV === "production" ? undefined : error.stack,
    });
  }
  res.status(status).json({
    error: error.code || "INTERNAL_ERROR",
    message: status >= 500 ? "服务暂时不可用，请稍后再试。" : error.message,
    details: error.details,
  });
});

if (process.env.NODE_ENV !== "test") {
  app.listen(config.port, "0.0.0.0", () => {
    console.log(`CIVIC volunteer API listening on port ${config.port}`);
  });
}

export { app };
