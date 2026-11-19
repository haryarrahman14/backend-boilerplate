import { refuseSelfChange } from './admin-rules.js';

const admin = { id: '3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b', role: 'admin' };
const other = '0b6f5a2e-1c3d-4e5f-8a9b-0c1d2e3f4a5b';

describe('refuseSelfChange', () => {
  it('allows anything on another user', () => {
    expect(refuseSelfChange(admin, other, { role: 'user', disabled: true })).toBeNull();
    expect(refuseSelfChange(admin, other, 'delete')).toBeNull();
  });

  it('refuses changing one’s own role, disabling or deleting oneself', () => {
    expect(refuseSelfChange(admin, admin.id, { role: 'user' })).toMatch(/own role/);
    expect(refuseSelfChange(admin, admin.id, { disabled: true })).toMatch(/disable themselves/);
    expect(refuseSelfChange(admin, admin.id, 'delete')).toMatch(/DELETE \/users\/me/);
    expect(refuseSelfChange(admin, admin.id.toUpperCase(), { disabled: true })).not.toBeNull();
  });

  it('allows self no-ops: nothing, the same role, or disabled: false', () => {
    expect(refuseSelfChange(admin, admin.id, {})).toBeNull();
    expect(refuseSelfChange(admin, admin.id, { role: 'admin' })).toBeNull();
    expect(refuseSelfChange(admin, admin.id, { disabled: false })).toBeNull();
    expect(refuseSelfChange(admin, admin.id, { role: 'admin', disabled: false })).toBeNull();
    expect(refuseSelfChange(admin, admin.id, { role: null, disabled: null })).toBeNull();
  });
});
