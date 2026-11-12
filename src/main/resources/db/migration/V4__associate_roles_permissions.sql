-- Associate USER role with USER_READ permission
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM role r
JOIN permission p ON p.name = 'USER_READ'
WHERE r.name = 'USER'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Associate ADMIN role with all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM role r
JOIN permission p ON p.name IN (
    'USER_READ',
    'USER_WRITE',
    'USER_DELETE'
)
WHERE r.name = 'ADMIN'
ON CONFLICT (role_id, permission_id) DO NOTHING;