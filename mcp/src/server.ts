/**
 * Colour Vault MCP Server
 *
 * Institutional deployment server for the Colour Vault protocol.
 * Runs entirely on the institution's own infrastructure.
 * No data leaves the institution's environment.
 *
 * Colour Foundation — buildwithcolours@gmail.com
 */

import express, { Request, Response, NextFunction } from "express";
import helmet from "helmet";
import cors from "cors";
import { z } from "zod";
import winston from "winston";

// ─── Logger ──────────────────────────────────────────────────────────────────
// IMPORTANT: The logger must never log sensitive data — keys, secrets, or
// wallet addresses beyond what is strictly necessary for audit trails.

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: "logs/colour-vault-mcp.log",
      maxsize: 10 * 1024 * 1024, // 10 MB
      maxFiles: 5,
    }),
  ],
});

// ─── Config Schema ────────────────────────────────────────────────────────────

const ConfigSchema = z.object({
  institution: z.string().min(1, "institution name required"),
  network: z.enum(["mainnet", "testnet"]),
  chains: z
    .array(z.enum(["bitcoin", "ethereum", "solana"]))
    .min(1, "at least one chain required"),
  mcp_host: z.string().default("127.0.0.1"),
  mcp_port: z.number().min(1024).max(65535).default(3847),
  quantum_layer: z.enum(["full", "signing-only"]).default("full"),
  log_level: z.enum(["debug", "info", "warn", "error"]).default("info"),
});

type Config = z.infer<typeof ConfigSchema>;

// ─── Request/Response Schemas ─────────────────────────────────────────────────

const VaultStatusSchema = z.object({
  institution: z.string(),
  version: z.string(),
  network: z.string(),
  chains: z.array(z.string()),
  quantum_layer: z.string(),
  uptime_seconds: z.number(),
  healthy: z.boolean(),
});

const ProvenanceCheckSchema = z.object({
  address: z.string().min(1),
  chain: z.enum(["bitcoin", "ethereum", "solana"]),
});

// ─── Server ───────────────────────────────────────────────────────────────────

export class ColourVaultMCPServer {
  private app: express.Application;
  private config: Config;
  private startTime: number;

  constructor(config: Config) {
    this.config = config;
    this.startTime = Date.now();
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandler();
  }

  private setupMiddleware(): void {
    // Security headers
    this.app.use(
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'"],
          },
        },
        hsts: {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true,
        },
      })
    );

    // Restrict CORS to localhost by default
    // Institutions should configure this to their specific internal origins
    this.app.use(
      cors({
        origin: process.env.ALLOWED_ORIGINS?.split(",") || [
          "http://localhost:3000",
          "http://127.0.0.1:3000",
        ],
        methods: ["GET", "POST"],
        allowedHeaders: ["Content-Type", "X-Institution-ID"],
      })
    );

    this.app.use(express.json({ limit: "1mb" }));

    // Request logging — no sensitive data
    this.app.use((req: Request, _res: Response, next: NextFunction) => {
      logger.info("request", {
        method: req.method,
        path: req.path,
        // Deliberately not logging body or query params
      });
      next();
    });
  }

  private setupRoutes(): void {
    // Health check — used by institution's infrastructure monitoring
    this.app.get("/health", (_req: Request, res: Response) => {
      const status = VaultStatusSchema.parse({
        institution: this.config.institution,
        version: "0.1.0",
        network: this.config.network,
        chains: this.config.chains,
        quantum_layer: this.config.quantum_layer,
        uptime_seconds: Math.floor((Date.now() - this.startTime) / 1000),
        healthy: true,
      });
      res.json(status);
    });

    // Provenance check endpoint
    // Validates wallet address format and delegates to analytics provider
    this.app.post(
      "/provenance/check",
      async (req: Request, res: Response, next: NextFunction) => {
        try {
          const body = ProvenanceCheckSchema.parse(req.body);

          // Validate address format before any external call
          const formatValid = this.validateAddressFormat(
            body.address,
            body.chain
          );
          if (!formatValid.valid) {
            return res.status(400).json({
              status: "rejected",
              reason: formatValid.reason,
            });
          }

          // In production: call configured analytics provider here
          // The provider is configured by the institution, not hardcoded
          // This keeps Colour Foundation out of the data flow entirely
          logger.info("provenance check requested", { chain: body.chain });

          return res.json({
            status: "format_valid",
            message:
              "Address format is valid. Configure an analytics provider for full provenance checking.",
            chain: body.chain,
          });
        } catch (error) {
          next(error);
        }
      }
    );

    // MCP capabilities declaration
    // Returned to clients to advertise what this server supports
    this.app.get("/mcp/capabilities", (_req: Request, res: Response) => {
      res.json({
        protocol_version: "0.1.0",
        capabilities: {
          vault_operations: ["sign", "verify", "rotate"],
          chains: this.config.chains,
          quantum_resistant: true,
          algorithms: {
            key_encapsulation: "ML-KEM-1024",
            signing: ["ML-DSA-87", "SPHINCS+-SHA2-256f"],
            symmetric: ["AES-256-GCM", "ChaCha20-Poly1305"],
            kdf: "Argon2id",
          },
          compliance: {
            nist_pqc: true,
            deterministic_builds: true,
            zero_data_custody: true,
          },
        },
      });
    });

    // Compliance bundle endpoint
    // Auto-generates a compliance report for institutional legal teams
    this.app.get(
      "/compliance/bundle",
      (_req: Request, res: Response) => {
        res.json({
          generated_at: new Date().toISOString(),
          institution: this.config.institution,
          deployment_type: "client_side_sovereign",
          data_custody: {
            user_keys: "none — keys stored in client device secure enclave",
            user_addresses: "none — not stored by this deployment",
            transaction_history: "none — not stored by this deployment",
            personal_data: "none — not collected or stored",
          },
          cryptographic_standards: {
            key_encapsulation: "ML-KEM-1024 (FIPS 203)",
            signing_primary: "ML-DSA-87 (FIPS 204)",
            signing_secondary: "SPHINCS+-SHA2-256f (FIPS 205)",
            symmetric_primary: "AES-256-GCM",
            symmetric_secondary: "ChaCha20-Poly1305",
            key_derivation: "Argon2id (RFC 9106)",
          },
          regulatory_notes: {
            custodian_status:
              "Colour Foundation is not a custodian. This institution operates this deployment on its own infrastructure.",
            kyc_aml:
              "KYC/AML obligations rest with this institution, not Colour Foundation.",
            data_protection:
              "No personal data is processed by the Colour Vault protocol.",
          },
          contact: "buildwithcolours@gmail.com",
        });
      }
    );
  }

  private validateAddressFormat(
    address: string,
    chain: string
  ): { valid: boolean; reason?: string } {
    switch (chain) {
      case "ethereum": {
        if (!address.startsWith("0x")) {
          return { valid: false, reason: "Ethereum address must start with 0x" };
        }
        if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
          return { valid: false, reason: "Invalid Ethereum address format" };
        }
        return { valid: true };
      }
      case "bitcoin": {
        if (!address.startsWith("bc1")) {
          return {
            valid: false,
            reason: "Only bech32 (bc1...) Bitcoin addresses accepted",
          };
        }
        if (address.length < 26 || address.length > 90) {
          return { valid: false, reason: "Invalid Bitcoin address length" };
        }
        return { valid: true };
      }
      case "solana": {
        if (address.length < 32 || address.length > 44) {
          return { valid: false, reason: "Invalid Solana address length" };
        }
        if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)) {
          return {
            valid: false,
            reason: "Invalid Solana address characters",
          };
        }
        return { valid: true };
      }
      default:
        return { valid: false, reason: `Unsupported chain: ${chain}` };
    }
  }

  private setupErrorHandler(): void {
    this.app.use(
      (err: Error, _req: Request, res: Response, _next: NextFunction) => {
        // Log the error internally but return minimal information externally
        // to avoid information leakage
        logger.error("unhandled error", { message: err.message });

        if (err instanceof z.ZodError) {
          return res.status(400).json({
            error: "invalid_request",
            details: err.errors.map((e) => ({
              field: e.path.join("."),
              message: e.message,
            })),
          });
        }

        return res.status(500).json({ error: "internal_error" });
      }
    );
  }

  public listen(): void {
    this.app.listen(this.config.mcp_port, this.config.mcp_host, () => {
      logger.info("Colour Vault MCP server started", {
        host: this.config.mcp_host,
        port: this.config.mcp_port,
        institution: this.config.institution,
        network: this.config.network,
        chains: this.config.chains,
      });
    });
  }
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

function loadConfig(): Config {
  const raw = {
    institution: process.env.INSTITUTION_NAME || "development",
    network: process.env.NETWORK || "testnet",
    chains: (process.env.CHAINS || "ethereum").split(","),
    mcp_host: process.env.MCP_HOST || "127.0.0.1",
    mcp_port: parseInt(process.env.MCP_PORT || "3847", 10),
    quantum_layer: process.env.QUANTUM_LAYER || "full",
    log_level: process.env.LOG_LEVEL || "info",
  };

  const result = ConfigSchema.safeParse(raw);
  if (!result.success) {
    logger.error("invalid configuration", { errors: result.error.errors });
    process.exit(1);
  }

  return result.data;
}

if (require.main === module) {
  const config = loadConfig();
  const server = new ColourVaultMCPServer(config);
  server.listen();
}
