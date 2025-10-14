export default function Footer() {
  return (
    <footer className="bottom-0 left-0 w-full bg-gray-50 border-t border-gray-200 py-4 text-center text-sm text-orange-500 z-50 shadow-md">
      <p>
        © {new Date().getFullYear()} SIEM Dashboard — Secure. Monitor. Defend.
      </p>
    </footer>
  );
}