/**
 * SPEC 4: DB driver errors must not put statement parameters in logs. Prisma's messages can echo a call's
 * arguments (password hashes included), so for those only the class and error code are kept.
 */
export function safeError(err: unknown): Error | Record<string, unknown> | string {
  if (err instanceof Error && (err.name.startsWith('PrismaClient') || err.constructor.name.startsWith('DriverAdapter'))) {
    return { msg: 'database error', error: err.name, code: (err as { code?: unknown }).code ?? null };
  }
  return err instanceof Error ? err : String(err);
}
