// Pure (unit tested): what an admin may not do to their own account through the admin routes.

export interface AdminUserChange {
  role?: 'user' | 'admin' | null; // null counts as absent (SPEC 5)
  disabled?: boolean | null;
}

/**
 * SPEC 5: an admin cannot change their own role, disable themselves, or delete themselves via /admin/users/{id}
 * (so nobody locks the system out by accident; self-deletion goes through DELETE /users/me). Returns the reason,
 * or null when allowed. Only an actual change is refused: re-sending one's current role, `disabled: false` (an
 * admin making the request is necessarily active) or nulls changes nothing and is allowed.
 */
export function refuseSelfChange(
  actor: { id: string; role: string },
  targetId: string,
  change: AdminUserChange | 'delete',
): string | null {
  if (actor.id !== targetId.toLowerCase()) return null;
  if (change === 'delete') return 'use DELETE /users/me to delete your own account';
  if (change.role != null && change.role !== actor.role) return 'admins cannot change their own role';
  if (change.disabled === true) return 'admins cannot disable themselves';
  return null;
}
