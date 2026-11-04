import { ForbiddenError, ValidationError } from "../errors/index.js";
import type { AuthSubject, MatcherCacheOptions, RBACOptions, RoleDefinition, StoredRole } from "../types/index.js";
import { isPlainObject, toArray, unique } from "../utils.js";
import { MatcherCache } from "./matcher-cache.js";

function normalizeName(value: unknown): string {
  return String(value).trim();
}

function asSet(values: unknown): Set<string> {
  return new Set(
    unique(toArray(values).map((item) => normalizeName(item)).filter(Boolean)),
  );
}

const MAX_SUBJECT_CACHE = 1_024;

const defaultMatcherCache = new MatcherCache();

export class RBAC {
  roles = new Map<string, StoredRole>();
  permissions = new Set<string>();
  rolePermissions = new Map<string, Set<string>>();
  roleParents = new Map<string, string[]>();
  defaultRole: string | null;
  public readonly matcherCache: MatcherCache;
  private compiledParents = new Map<string, string[]>();
  private compiledPermissions = new Map<string, Set<string>>();
  private compiledRevision = 0;
  private subjectCache = new Map<string, { revision: number; permissions: Set<string> }>();

  constructor(options: RBACOptions = {}) {
    this.defaultRole = options.defaultRole ?? null;
    this.matcherCache = new MatcherCache(options.matcherCache);

    if (Array.isArray(options.permissions)) {
      for (const permission of options.permissions) {
        this.addPermission(permission);
      }
    }

    if (isPlainObject(options.roles)) {
      for (const [role, config] of Object.entries(options.roles)) {
        this.addRole(role, config);
      }
    } else if (Array.isArray(options.roles)) {
      for (const role of options.roles) {
        this.addRole(role);
      }
    }
    this.recompile();
  }

  addPermission(permission: string): this {
    const name = normalizeName(permission);
    if (!name) {
      throw new ValidationError("Permission name is required");
    }
    this.permissions.add(name);
    this.invalidateCompilation();
    return this;
  }

  addRole(role: string | RoleDefinition, config: RoleDefinition = {}): this {
    const name = normalizeName(typeof role === "string" ? role : role?.name);
    if (!name) {
      throw new ValidationError("Role name is required");
    }

    const definition = isPlainObject(config) ? config : {};
    const permissions = asSet(definition.permissions ?? definition.perms);
    const inherits = unique(
      toArray(definition.inherits ?? definition.parents ?? definition.parent).map(normalizeName).filter(Boolean),
    );

    // Validate that adding these inheritance edges won't create a cycle,
    // before committing any state mutation.
    const nextParents = unique([
      ...(this.roleParents.get(name) ?? []),
      ...inherits,
    ]);
    const previousParents = this.roleParents.get(name);
    this.roleParents.set(name, nextParents);
    try {
      this.detectCycle(name);
    } catch (error) {
      if (previousParents === undefined) {
        this.roleParents.delete(name);
      } else {
        this.roleParents.set(name, previousParents);
      }
      throw error;
    }

    for (const permission of permissions) {
      this.permissions.add(permission);
    }

    this.roles.set(name, {
      name,
      description: typeof definition.description === "string" ? definition.description : "",
    });
    this.rolePermissions.set(name, new Set([
      ...(this.rolePermissions.get(name) ?? []),
      ...permissions,
    ]));
    this.invalidateCompilation();

    return this;
  }

  grant(role: string, permissions: string | string[]): this {
    const name = this.requireRole(role);
    const granted = asSet(permissions);
    const current = this.rolePermissions.get(name) ?? new Set<string>();
    for (const permission of granted) {
      this.permissions.add(permission);
      current.add(permission);
    }
    this.rolePermissions.set(name, current);
    this.invalidateCompilation();
    return this;
  }

  revoke(role: string, permissions: string | string[]): this {
    const name = this.requireRole(role);
    const current = this.rolePermissions.get(name) ?? new Set<string>();
    for (const permission of asSet(permissions)) {
      current.delete(permission);
    }
    this.rolePermissions.set(name, current);
    this.invalidateCompilation();
    return this;
  }

  inherit(role: string, parents: string | string[]): this {
    const name = this.requireRole(role);
    const next = unique([
      ...(this.roleParents.get(name) ?? []),
      ...toArray(parents).map(normalizeName).filter(Boolean),
    ]);
    const previous = this.roleParents.get(name);
    this.roleParents.set(name, next);
    try {
      this.detectCycle(name);
    } catch (error) {
      if (previous === undefined) {
        this.roleParents.delete(name);
      } else {
        this.roleParents.set(name, previous);
      }
      throw error;
    }
    this.invalidateCompilation();
    return this;
  }

  hasRole(role: string): boolean {
    return this.roles.has(normalizeName(role));
  }

  requireRole(role: string): string {
    const name = normalizeName(role);
    if (!this.roles.has(name)) {
      throw new ValidationError(`Unknown role: ${role}`);
    }
    return name;
  }

  getRoles(): string[] {
    return [...this.roles.keys()];
  }

  getPermissions(role?: string): string[] {
    if (role === undefined) {
      return [...this.permissions];
    }
    return [...this.resolvePermissions(role)];
  }

  resolveParents(role: string, seen = new Set<string>()): string[] {
    const name = normalizeName(role);
    const compiled = this.compiledParents.get(name);
    if (compiled && seen.size === 0) {
      return [...compiled];
    }
    if (!this.roles.has(name) || seen.has(name)) {
      return [];
    }

    seen.add(name);
    const parents: string[] = [];
    for (const parent of this.roleParents.get(name) ?? []) {
      parents.push(parent, ...this.resolveParents(parent, seen));
    }
    return unique(parents);
  }

  resolvePermissions(role: string): Set<string> {
    const name = normalizeName(role);
    const compiled = this.compiledPermissions.get(name);
    if (compiled) {
      return new Set(compiled);
    }
    const resolved = new Set(this.rolePermissions.get(name) ?? []);
    for (const parent of this.resolveParents(name)) {
      for (const permission of this.rolePermissions.get(parent) ?? []) {
        resolved.add(permission);
      }
    }
    return resolved;
  }

  subjectRoles(subject?: AuthSubject | string | null): string[] {
    // A missing subject never receives the default role, so null/undefined
    // cannot be granted privileges by configuration.
    if (subject === null || subject === undefined) {
      return [];
    }
    if (typeof subject === "string" && subject === "") {
      return [];
    }

    if (typeof subject === "string") {
      return [normalizeName(subject)];
    }

    const roles = unique([
      ...toArray(subject.roles),
      ...toArray(subject.role),
    ].map(normalizeName).filter(Boolean));

    if (roles.length === 0 && this.defaultRole) {
      return [this.defaultRole];
    }

    return roles;
  }

  subjectPermissions(subject?: AuthSubject | string | null): Set<string> {
    const roles = this.subjectRoles(subject);
    const record = typeof subject === "object" && subject ? subject : undefined;
    const direct = asSet(record?.permissions);
    const cacheKey = `${roles.join("\0")}#${[...direct].join("\0")}`;
    const cached = this.subjectCache.get(cacheKey);
    if (cached && cached.revision === this.compiledRevision) {
      return new Set(cached.permissions);
    }
    const resolved = new Set(direct);
    for (const role of roles) {
      for (const permission of this.resolvePermissions(role)) {
        resolved.add(permission);
      }
    }
    if (this.subjectCache.size >= MAX_SUBJECT_CACHE) {
      const oldest = this.subjectCache.keys().next().value;
      if (oldest !== undefined) {
        this.subjectCache.delete(oldest);
      }
    }
    this.subjectCache.set(cacheKey, { revision: this.compiledRevision, permissions: new Set(resolved) });
    return resolved;
  }

  can(subject: AuthSubject | string | null | undefined, permission: string | string[]): boolean {
    if (!permission) {
      return false;
    }
    const needed = asSet(permission);
    const owned = this.subjectPermissions(subject);
    for (const item of needed) {
      if (owned.has(item) || owned.has("*")) {
        continue;
      }
      if (![...owned].some((granted) => this.matchPattern(granted, item))) {
        return false;
      }
    }
    return needed.size > 0;
  }

  private matchPattern(granted: string, needed: string): boolean {
    if (granted === needed || granted === "*") {
      return true;
    }
    if (!granted.includes("*")) {
      return false;
    }
    let matcher = this.matcherCache.get(granted);
    if (!matcher) {
      matcher = buildPermissionRegex(granted);
      this.matcherCache.set(granted, matcher);
    }
    return matcher.test(needed);
  }

  cannot(subject: AuthSubject | string | null | undefined, permission: string | string[]): boolean {
    return !this.can(subject, permission);
  }

  authorize(subject: AuthSubject | string | null | undefined, permission: string | string[]): true {
    if (!this.can(subject, permission)) {
      throw new ForbiddenError(`Missing permission: ${toArray(permission).join(", ")}`);
    }
    return true;
  }

  hasAnyRole(subject: AuthSubject | string | null | undefined, roles: string | string[]): boolean {
    const owned = new Set(this.subjectRoles(subject));
    return toArray(roles).some((role) => owned.has(normalizeName(role)));
  }

  hasAllRoles(subject: AuthSubject | string | null | undefined, roles: string | string[]): boolean {
    const owned = new Set(this.subjectRoles(subject));
    const needed = toArray(roles).map(normalizeName).filter(Boolean);
    return needed.length > 0 && needed.every((role) => owned.has(role));
  }

  snapshot(): {
    defaultRole: string | null;
    permissions: string[];
    roles: Record<string, { description: string; permissions: string[]; inherits: string[] }>;
  } {
    const roles: Record<string, { description: string; permissions: string[]; inherits: string[] }> = {};
    for (const name of this.roles.keys()) {
      roles[name] = {
        description: this.roles.get(name)?.description ?? "",
        permissions: [...(this.rolePermissions.get(name) ?? [])],
        inherits: [...(this.roleParents.get(name) ?? [])],
      };
    }
    return {
      defaultRole: this.defaultRole,
      permissions: [...this.permissions],
      roles,
    };
  }

  invalidate(): void {
    this.invalidateCompilation();
  }

  private invalidateCompilation(): void {
    this.compiledRevision += 1;
    this.subjectCache.clear();
    this.recompile();
  }

  private recompile(): void {
    this.compiledParents.clear();
    this.compiledPermissions.clear();
    for (const name of this.roles.keys()) {
      this.detectCycle(name);
      const parents = this.computeParents(name);
      this.compiledParents.set(name, parents);
      const resolved = new Set(this.rolePermissions.get(name) ?? []);
      for (const parent of parents) {
        for (const permission of this.rolePermissions.get(parent) ?? []) {
          resolved.add(permission);
        }
      }
      this.compiledPermissions.set(name, resolved);
    }
  }

  private computeParents(role: string): string[] {
    const seen = new Set<string>([role]);
    const parents: string[] = [];
    const stack = [...(this.roleParents.get(role) ?? [])];
    while (stack.length > 0) {
      const current = stack.pop();
      if (!current || seen.has(current)) {
        continue;
      }
      seen.add(current);
      parents.push(current);
      for (const parent of this.roleParents.get(current) ?? []) {
        stack.push(parent);
      }
    }
    return unique(parents);
  }

  private detectCycle(role: string): void {
    const visiting = new Set<string>();
    const visited = new Set<string>();
    const walk = (name: string, path: string[]): void => {
      if (visiting.has(name)) {
        throw new ValidationError(`Cyclic role inheritance: ${[...path, name].join(" -> ")}`);
      }
      if (visited.has(name)) {
        return;
      }
      visiting.add(name);
      for (const parent of this.roleParents.get(name) ?? []) {
        walk(parent, [...path, name]);
      }
      visiting.delete(name);
      visited.add(name);
    };
    walk(role, []);
  }
}

function buildPermissionRegex(granted: string): RegExp {
  const pattern = granted
    .split(/[.:]/)
    .map((part) => {
      if (part === "**") return ".*";
      if (part === "*") return "[^.]+";
      return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("[.:]");
  return new RegExp(`^${pattern}$`);
}

export function matchPermission(granted: string, needed: string): boolean {
  if (granted === needed || granted === "*") {
    return true;
  }
  let matcher = defaultMatcherCache.get(granted);
  if (!matcher) {
    matcher = buildPermissionRegex(granted);
    defaultMatcherCache.set(granted, matcher);
  }
  return matcher.test(needed);
}

export { MatcherCache };
export type { MatcherCacheOptions };

export function createRBAC(options: RBACOptions = {}): RBAC {
  return new RBAC(options);
}

export function defineRoles(roles: RBACOptions["roles"]): RBAC {
  return createRBAC({ roles });
}
