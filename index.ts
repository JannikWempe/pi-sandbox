/**
 * pi-sandbox
 *
 * Standalone OS-level sandboxing for pi bash commands using bubblewrap (bwrap).
 * Also checks pi file tools against the same path policy.
 *
 * Config files, merged in this order:
 *   - ~/.pi/agent/pi-sandbox.json
 *   - <cwd>/.pi/pi-sandbox.json
 */

import {
	createBashTool,
	isToolCallEventType,
	type BashOperations,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";
import {
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

const EXTENSION_NAME = "pi-sandbox";
const USER_CONFIG_PATH = join(homedir(), ".pi", "agent", "pi-sandbox.json");

const DEFAULT_ENV_DENY = ["*_TOKEN", "*_SECRET", "*_PASSWORD", "*_KEY"];

const DEFAULT_PRIVATE_PATHS = [
	"~/Private",
	"~/.ssh",
	"~/.config",
	"~/.aws",
	"~/.azure",
	"~/.gcloud",
	"~/.oci",
	"~/.kube",
	"~/.docker",
	"~/.gnupg",
	"~/.sops",
	"~/.age",
	"~/.password-store",
	"~/.terraform.d",
	"~/.vault-token",
	"~/.netrc",
	"~/.npmrc",
	"~/.pypirc",
	"~/.cargo/credentials",
	"~/.cargo/credentials.toml",
	"~/.claude",
	"~/.codex",
	"~/.forge",
	"~/.cursor",
	"~/.windsurf",
	"~/.openai",
	"~/.anthropic",
];

export interface SandboxConfig {
	enabled?: boolean;
	network?: "host" | "none";
	paths?: Record<string, SandboxPathEntry | SandboxPathEntry[]>;
	env?: {
		allow?: string[] | null;
		deny?: string[] | null;
		set?: Record<string, string | null>;
	};
}

export interface SandboxPathEntry {
	/** Exact host/sandbox path for this entry. Without this, the paths key is a prefix. */
	path?: string;
	/** Synthetic read-only file content to expose at path. */
	content?: string;
	/** Defaults to read. */
	mode?: "read" | "write" | "deny";
}

export interface NormalizedSandboxConfig {
	enabled: boolean;
	network: "host" | "none";
	paths: Record<string, SandboxPathEntry[]>;
	env: {
		allow: string[] | null;
		deny: string[] | null;
		set: Record<string, string | null>;
	};
}

export interface SandboxPathAccess {
	access: "none" | "read" | "write";
	synthetic: boolean;
	matchedPath?: string;
}

const DEFAULT_PRIVATE_PATH_DENIES = Object.fromEntries(
	DEFAULT_PRIVATE_PATHS.map((path) => [path, { mode: "deny" } satisfies SandboxPathEntry]),
) as Record<string, SandboxPathEntry>;

const DEFAULT_PATHS: Record<string, SandboxPathEntry | SandboxPathEntry[]> = {
	".": { mode: "write" },
	"/tmp": { mode: "write" },
	"~/.pi": { mode: "write" },
	...DEFAULT_PRIVATE_PATH_DENIES,

	"/usr": {},
	"/opt": {},
	"/srv": {},
	"/etc": {},
	"/nix/store": {},
	"/run/current-system/sw": {},

	// Non-usr-merged Linux compatibility. Harmless on modern distros.
	"/bin": {},
	"/sbin": {},
	"/lib": {},
	"/lib64": {},
};

const DEFAULT_SANDBOX_CONFIG: NormalizedSandboxConfig = {
	enabled: false,
	network: "host",
	paths: normalizePaths(DEFAULT_PATHS),
	env: {
		allow: null,
		deny: DEFAULT_ENV_DENY,
		set: {},
	},
};

function hasOwn<T extends object, K extends PropertyKey>(obj: T | undefined, key: K): obj is T & Record<K, unknown> {
	return !!obj && Object.prototype.hasOwnProperty.call(obj, key);
}

function normalizePaths(
	paths: Record<string, SandboxPathEntry | SandboxPathEntry[]> = {},
): Record<string, SandboxPathEntry[]> {
	const result: Record<string, SandboxPathEntry[]> = {};
	for (const [prefix, entries] of Object.entries(paths)) {
		result[prefix] = (Array.isArray(entries) ? entries : [entries]).map((entry) => ({ ...entry }));
	}
	return result;
}

function mergeSandboxConfig(base: SandboxConfig, override: SandboxConfig): SandboxConfig {
	return {
		enabled: hasOwn(override, "enabled") ? override.enabled : base.enabled,
		network: hasOwn(override, "network") ? override.network : base.network,
		paths: {
			...(base.paths ?? {}),
			...(override.paths ?? {}),
		},
		env: {
			allow: hasOwn(override.env, "allow") ? override.env.allow : base.env?.allow,
			deny: hasOwn(override.env, "deny") ? override.env.deny : base.env?.deny,
			set: {
				...(base.env?.set ?? {}),
				...(override.env?.set ?? {}),
			},
		},
	};
}

function normalizeSandboxConfig(config: SandboxConfig = {}): NormalizedSandboxConfig {
	const mergedPaths = expandPathKeys({
		...DEFAULT_SANDBOX_CONFIG.paths,
		...normalizePaths(config.paths),
	});

	// Add HOME as read-only by default so tools can reference non-sensitive config files.
	// Private defaults above are masked/blocked separately.
	const homeDir = process.env.HOME;
	if (homeDir && !(homeDir in mergedPaths)) {
		mergedPaths[homeDir] = [{}];
	}

	return {
		enabled: config.enabled ?? DEFAULT_SANDBOX_CONFIG.enabled,
		network: config.network ?? DEFAULT_SANDBOX_CONFIG.network,
		paths: mergedPaths,
		env: {
			allow: hasOwn(config.env, "allow") && config.env.allow !== undefined ? config.env.allow : DEFAULT_SANDBOX_CONFIG.env.allow,
			deny: hasOwn(config.env, "deny") && config.env.deny !== undefined ? config.env.deny : DEFAULT_SANDBOX_CONFIG.env.deny,
			set: config.env?.set ?? DEFAULT_SANDBOX_CONFIG.env.set,
		},
	};
}

function readConfigFile(path: string): SandboxConfig {
	if (!existsSync(path)) return {};
	try {
		return JSON.parse(readFileSync(path, "utf-8")) as SandboxConfig;
	} catch (error) {
		throw new Error(`Failed to read ${EXTENSION_NAME} config at ${path}: ${error instanceof Error ? error.message : String(error)}`);
	}
}

function loadSandboxConfig(cwd: string): NormalizedSandboxConfig {
	const projectConfigPath = join(cwd, ".pi", "pi-sandbox.json");
	const merged = mergeSandboxConfig(
		readConfigFile(USER_CONFIG_PATH),
		readConfigFile(projectConfigPath),
	);
	return normalizeSandboxConfig(merged);
}

/** Resolve ~ and $VAR/${VAR} references in path strings. */
function expandPath(path: string): string {
	if (path.startsWith("~")) {
		if (path === "~" || path.startsWith("~/")) {
			const home = process.env.HOME;
			if (home) return home + path.slice(1);
		}
	}
	return path.replace(/\$\{?(\w+)\}?/g, (_m, name: string) => process.env[name] ?? "");
}

function expandPathKeys<T extends SandboxPathEntry>(paths: Record<string, T[]>): Record<string, T[]> {
	const result: Record<string, T[]> = {};
	for (const [key, entries] of Object.entries(paths)) {
		result[expandPath(key)] = entries;
	}
	return result;
}

function resolveSandboxPath(path: string, cwd: string): string {
	const expanded = expandPath(path);
	if (expanded === ".") return cwd;
	return expanded.startsWith("/") ? expanded : resolve(cwd, expanded);
}

function pathMatchesPrefix(path: string, prefix: string): boolean {
	return path === prefix || path.startsWith(`${prefix}/`);
}

export function getSandboxPathAccess(
	config: NormalizedSandboxConfig,
	cwd: string,
	rawPath: string,
): SandboxPathAccess {
	const target = resolveSandboxPath(rawPath.replace(/^@/, ""), cwd);
	let best: { specificity: number; order: number; access: "none" | "read" | "write"; synthetic: boolean; matchedPath: string } | null = null;
	let order = 0;

	for (const [prefix, entries] of Object.entries(config.paths)) {
		for (const entry of entries) {
			const entryTarget = resolveSandboxPath(entry.path ?? prefix, cwd);
			const matches = entry.path ? target === entryTarget : pathMatchesPrefix(target, entryTarget);
			if (!matches) {
				order++;
				continue;
			}

			const candidate = {
				specificity: entryTarget.length + (entry.path ? 10_000 : 0),
				order,
				access: entry.mode === "write" ? "write" as const : entry.mode === "deny" ? "none" as const : "read" as const,
				synthetic: entry.content !== undefined,
				matchedPath: entryTarget,
			};
			if (!best || candidate.specificity > best.specificity ||
				(candidate.specificity === best.specificity && candidate.order > best.order)) {
				best = candidate;
			}
			order++;
		}
	}

	return best
		? { access: best.access, synthetic: best.synthetic, matchedPath: best.matchedPath }
		: { access: "none", synthetic: false };
}

function canReadSandboxPath(config: NormalizedSandboxConfig, cwd: string, path: string): boolean {
	const access = getSandboxPathAccess(config, cwd, path);
	// Synthetic files only exist inside bwrap; host read would expose the real host file instead.
	return access.access !== "none" && !access.synthetic;
}

function canWriteSandboxPath(config: NormalizedSandboxConfig, cwd: string, path: string): boolean {
	const access = getSandboxPathAccess(config, cwd, path);
	return access.access === "write" && !access.synthetic;
}

function isCompatibilitySymlink(path: string, mountedPrefixes: Set<string>): boolean {
	try {
		const stat = lstatSync(path);
		if (!stat.isSymbolicLink()) return false;
		const target = resolve(path);
		for (const prefix of mountedPrefixes) {
			if (target === prefix || target.startsWith(`${prefix}/`)) return true;
		}
	} catch {
		return false;
	}
	return false;
}

function syntheticFilename(target: string): string {
	return target.replace(/[^a-zA-Z0-9._-]/g, "_") || "synthetic";
}

function writeSyntheticFile(syntheticDir: string, target: string, content: string): string {
	const syntheticFile = join(syntheticDir, syntheticFilename(target));
	writeFileSync(syntheticFile, content, "utf-8");
	return syntheticFile;
}

function createEmptyMask(syntheticDir: string, target: string): { kind: "tmpfs"; target: string } | { kind: "file"; source: string; target: string } | null {
	try {
		const stat = lstatSync(target);
		if (stat.isDirectory()) return { kind: "tmpfs", target };
		const source = writeSyntheticFile(syntheticDir, `${target}.mask`, "");
		return { kind: "file", source, target };
	} catch {
		return null;
	}
}

export function buildBwrapArgs(
	config: NormalizedSandboxConfig,
	cwd: string,
	syntheticDir: string,
	command: string,
): string[] {
	const args: string[] = [];
	const readPrefixMounts: string[] = [];
	const writeMounts: string[] = [];
	const overlayReadMounts: Array<{ source: string; target: string }> = [];
	const masks: Array<{ kind: "tmpfs"; target: string } | { kind: "file"; source: string; target: string }> = [];

	args.push("--tmpfs", "/");
	args.push("--dev", "/dev");

	for (const [prefix, entries] of Object.entries(config.paths)) {
		for (const entry of entries) {
			const target = resolveSandboxPath(entry.path ?? prefix, cwd);
			if (entry.content !== undefined) {
				const syntheticFile = writeSyntheticFile(syntheticDir, target, entry.content);
				overlayReadMounts.push({ source: syntheticFile, target });
				continue;
			}

			if (entry.mode === "deny") {
				const mask = createEmptyMask(syntheticDir, target);
				if (mask) masks.push(mask);
				continue;
			}
			if (!existsSync(target)) continue;

			if (entry.mode === "write") {
				writeMounts.push(target);
			} else if (entry.path) {
				overlayReadMounts.push({ source: target, target });
			} else {
				readPrefixMounts.push(target);
			}
		}
	}

	const mountedReadPrefixes = new Set<string>();
	for (const target of dedupe(readPrefixMounts)) {
		if (isCompatibilitySymlink(target, mountedReadPrefixes)) continue;
		args.push("--ro-bind", target, target);
		mountedReadPrefixes.add(target);
	}

	for (const target of dedupe(writeMounts)) {
		args.push("--bind", target, target);
	}

	for (const { source, target } of dedupeMounts(overlayReadMounts)) {
		args.push("--ro-bind", source, target);
	}

	// Apply denied-path masks last so they hide any broader parent mount.
	for (const mask of dedupeMasks(masks)) {
		if (mask.kind === "tmpfs") args.push("--tmpfs", mask.target);
		else args.push("--ro-bind", mask.source, mask.target);
	}

	args.push("--unshare-user");
	args.push("--unshare-pid");
	if (config.network === "none") args.push("--unshare-net");
	args.push("--proc", "/proc");
	args.push("--die-with-parent");
	args.push("--new-session");
	args.push("--");
	args.push("bash", "-c", command);

	return args;
}

function dedupe(values: string[]): string[] {
	return [...new Set(values)];
}

function dedupeMounts(mounts: Array<{ source: string; target: string }>): Array<{ source: string; target: string }> {
	const seen = new Set<string>();
	const result: Array<{ source: string; target: string }> = [];
	for (const mount of mounts) {
		const key = `${mount.source}\0${mount.target}`;
		if (seen.has(key)) continue;
		seen.add(key);
		result.push(mount);
	}
	return result;
}

function dedupeMasks<T extends { target: string }>(masks: T[]): T[] {
	const result = new Map<string, T>();
	for (const mask of masks) result.set(mask.target, mask);
	return [...result.values()];
}

function globToRegExp(pattern: string): RegExp {
	const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
	return new RegExp(`^${escaped}$`);
}

export function filterEnv(
	envConfig: NormalizedSandboxConfig["env"],
	currentEnv: Record<string, string>,
): Record<string, string> {
	const allow = envConfig.allow;
	const deny = envConfig.deny;
	const allowPatterns = allow?.map(globToRegExp) ?? null;
	const denyPatterns = deny?.map(globToRegExp) ?? [];
	const result: Record<string, string> = {};

	for (const [key, value] of Object.entries(currentEnv)) {
		const allowed = allowPatterns === null || allowPatterns.some((pattern) => pattern.test(key));
		const denied = denyPatterns.some((pattern) => pattern.test(key));
		if (allowed && !denied) result[key] = value;
	}

	for (const [key, value] of Object.entries(envConfig.set ?? {})) {
		if (value === null) delete result[key];
		else result[key] = value;
	}

	return result;
}

function findBwrap(): string | null {
	const pathEnv = process.env.PATH ?? "";
	for (const dir of pathEnv.split(":")) {
		const candidate = join(dir, "bwrap");
		if (existsSync(candidate)) return candidate;
	}
	for (const loc of ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]) {
		if (existsSync(loc)) return loc;
	}
	return null;
}

function createSandboxedBashOps(config: NormalizedSandboxConfig, cwd: string): BashOperations {
	return {
		async exec(command, execCwd, { onData, signal, timeout }) {
			const workDir = execCwd || cwd;
			if (!existsSync(workDir)) {
				throw new Error(`Working directory does not exist: ${workDir}`);
			}

			const syntheticDir = join(
				process.env.TMPDIR || "/tmp",
				`${EXTENSION_NAME}-${randomUUID()}`,
			);
			mkdirSync(syntheticDir, { recursive: true });

			try {
				const bwrapPath = findBwrap();
				if (!bwrapPath) {
					throw new Error("bubblewrap (bwrap) not found. Install it to enable sandboxing.");
				}

				const bwrapArgs = buildBwrapArgs(config, cwd, syntheticDir, command);
				const cleanEnv = filterEnv(config.env, process.env as Record<string, string>);

				return await new Promise((resolve, reject) => {
					const child = spawn(bwrapPath, bwrapArgs, {
						cwd: workDir,
						env: cleanEnv,
						detached: true,
						stdio: ["ignore", "pipe", "pipe"],
					});

					let timedOut = false;
					let timeoutHandle: NodeJS.Timeout | undefined;

					if (timeout !== undefined && timeout > 0) {
						timeoutHandle = setTimeout(() => {
							timedOut = true;
							if (child.pid) {
								try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
							}
						}, timeout * 1000);
					}

					child.stdout?.on("data", onData);
					child.stderr?.on("data", onData);

					child.on("error", (err) => {
						if (timeoutHandle) clearTimeout(timeoutHandle);
						reject(err);
					});

					const onAbort = () => {
						if (child.pid) {
							try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
						}
					};

					signal?.addEventListener("abort", onAbort, { once: true });

					child.on("close", (code) => {
						if (timeoutHandle) clearTimeout(timeoutHandle);
						signal?.removeEventListener("abort", onAbort);

						if (signal?.aborted) reject(new Error("aborted"));
						else if (timedOut) reject(new Error(`timeout:${timeout}`));
						else resolve({ exitCode: code ?? 1 });
					});
				});
			} finally {
				try { rmSync(syntheticDir, { recursive: true, force: true }); } catch { /* best effort */ }
			}
		},
	};
}

export default function registerPiSandbox(pi: ExtensionAPI): void {
	let sandboxConfig: NormalizedSandboxConfig | null = null;
	let sandboxCwd = process.cwd();
	let bwrapAvailable = false;

	pi.registerFlag("no-sandbox", {
		description: "Disable pi-sandbox OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	pi.on("session_start", async (_event, ctx) => {
		sandboxCwd = ctx.cwd;
		const noSandbox = pi.getFlag("no-sandbox") as boolean;
		if (noSandbox) {
			sandboxConfig = null;
			bwrapAvailable = false;
			ctx.ui.notify(`${EXTENSION_NAME}: disabled via --no-sandbox`, "warning");
			return;
		}

		let config: NormalizedSandboxConfig;
		try {
			config = loadSandboxConfig(ctx.cwd);
		} catch (error) {
			sandboxConfig = null;
			bwrapAvailable = false;
			ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
			return;
		}

		sandboxConfig = null;
		bwrapAvailable = false;
		if (!config.enabled) return;

		if (process.platform !== "linux") {
			ctx.ui.notify(`${EXTENSION_NAME}: not supported on ${process.platform} (Linux only)`, "warning");
			return;
		}

		const bwrap = findBwrap();
		if (!bwrap) {
			ctx.ui.notify(`${EXTENSION_NAME}: bwrap not found. Install bubblewrap to enable sandboxing.`, "warning");
			return;
		}

		bwrapAvailable = true;
		sandboxConfig = config;

		const entries = Object.values(config.paths).flat();
		const writeCount = entries.filter((entry) => entry.mode === "write").length;
		const envIcon = config.env.allow === null ? "E∞" : `E${config.env.allow.length}`;
		const networkIcon = config.network === "host" ? "↔" : "⊘";
		const theme = ctx.ui.theme;
		ctx.ui.setStatus(
			EXTENSION_NAME,
			[
				theme.fg("accent", "🛡"),
				theme.fg("success", `✎${writeCount}`),
				theme.fg("muted", envIcon),
				theme.fg(config.network === "host" ? "success" : "warning", networkIcon),
			].join(theme.fg("dim", "│")),
		);
		ctx.ui.notify(`${EXTENSION_NAME}: active`, "info");
	});

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	pi.registerTool({
		...localBash,
		label: "bash (pi-sandbox)",
		async execute(id, params, signal, onUpdate, _ctx) {
			if (!sandboxConfig || !bwrapAvailable) {
				return localBash.execute(id, params, signal, onUpdate);
			}

			const sandboxedBash = createBashTool(sandboxCwd, {
				operations: createSandboxedBashOps(sandboxConfig, sandboxCwd),
			});
			return sandboxedBash.execute(id, params, signal, onUpdate);
		},
	});

	pi.on("user_bash", () => {
		if (!sandboxConfig || !bwrapAvailable) return undefined;
		return {
			operations: createSandboxedBashOps(sandboxConfig, sandboxCwd),
		};
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!sandboxConfig || !sandboxConfig.enabled) return undefined;

		const block = (operation: "read" | "write", path: string) => {
			const reason =
				`Blocked: ${event.toolName} attempted to ${operation} "${path}" outside the ${EXTENSION_NAME} path policy. ` +
				`Use a path mounted with ${operation === "write" ? 'mode "write"' : "read access"} in paths, or adjust .pi/pi-sandbox.json.`;
			if (ctx.hasUI) ctx.ui.notify(`${EXTENSION_NAME}: blocked ${event.toolName} ${path}`, "warning");
			return { block: true as const, reason };
		};

		const input = event.input as Record<string, unknown>;
		const path = typeof input.path === "string" ? input.path : ".";

		if (isToolCallEventType("read", event) || event.toolName === "grep" || event.toolName === "find" || event.toolName === "ls") {
			if (!canReadSandboxPath(sandboxConfig, sandboxCwd, path)) return block("read", path);
			return undefined;
		}

		if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
			if (typeof input.path !== "string") return undefined;
			if (!canWriteSandboxPath(sandboxConfig, sandboxCwd, input.path)) return block("write", input.path);
		}

		return undefined;
	});

	pi.registerCommand("sandbox", {
		description: "Show pi-sandbox configuration",
		handler: async (_args, ctx) => {
			if (!sandboxConfig) {
				ctx.ui.notify(`${EXTENSION_NAME}: disabled`, "info");
				return;
			}

			const lines = [
				"pi-sandbox configuration:",
				"",
				`Config files: ${USER_CONFIG_PATH}, ${join(ctx.cwd, ".pi", "pi-sandbox.json")}`,
				`Network: ${sandboxConfig.network === "host" ? "shared (host)" : "isolated"}`,
				`Env allow: ${sandboxConfig.env.allow === null ? "inherited" : sandboxConfig.env.allow.join(", ")}`,
				`Env deny: ${sandboxConfig.env.deny?.join(", ") || "(none)"}`,
				"Paths:",
				...Object.entries(sandboxConfig.paths).flatMap(([prefix, entries]) =>
					entries.map((entry) => {
						const target = entry.path ?? prefix;
						const kind = entry.content === undefined ? target : `${target} (synthetic)`;
						return `  ${prefix}: ${kind} [${entry.mode ?? "read"}]`;
					}),
				),
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
