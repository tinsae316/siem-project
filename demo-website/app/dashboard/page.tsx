export default function DashboardPage() {
  return (
    <div style={{ maxWidth: 500, margin: 'auto', padding: 32 }}>
      <h2>Welcome to the SIEM Demo Dashboard</h2>
      <p>This is the protected area after successful login.</p>
      <a href="/login">Logout</a>
    </div>
  );
}
