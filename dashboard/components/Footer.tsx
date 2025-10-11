export default function Footer() {
  return (
    <footer className="bg-gray-50 border-t border-gray-200 py-4 text-center text-sm text-orange-500 mt-auto">
      <p>
        © {new Date().getFullYear()} SIEM Dashboard - Secure. Monitor. Defend.
      </p>
    </footer>
  );
}