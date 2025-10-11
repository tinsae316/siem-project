import { FLIGHT_HEADERS } from "next/dist/client/components/app-router-headers";
import Link from "next/link";
import { useRouter } from "next/router";
import { FiBookOpen, FiLogOut, FiShield } from "react-icons/fi";

const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    // you previously redirected to /landing
    window.location.href = "/landing";
  };
export default function Header() {
  const router = useRouter();
  return (
    <header className="bg-gray-900 text-white shadow-md" >
      <div className="max-w-6xl mx-auto flex items-center justify-between px-24 py-2">
        <Link href="/" className="flex items-center gap-2 text-xl font-semibold">
          <FiShield className="text-orange-500  h-6 w-6" />
          <span>SIEM Dashboard</span>
        </Link>
        <nav className="flex gap-4 text-sm">
           <Link
  href="/about"
  className={`flex items-center gap-1 ${
    router.pathname === "/about"
      ? "border-b-2 border-orange-500 text-orange-500 pb-1 transition-all duration-300"
      : "hover:text-orange-400 transition-all duration-300 px-2 py-1.5 rounded-md"
  }`}
>
  <FiBookOpen className="h-4 w-4" />
  <span>About</span>
</Link>
           <button
              onClick={handleLogout}
                className="place-items-right bg-red-500 hover:bg-red-600 text-white px-6 py-4.5 rounded-md text-sm font-medium shadow-md flex items-center gap-1">
                <FiLogOut className="h-4 w-4" /> Logout
           </button>
          </nav>
      </div>
    </header>

  );
}