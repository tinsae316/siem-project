"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { FiEye, FiAlertTriangle, FiBarChart2, FiLock, FiUsers, FiGlobe } from "react-icons/fi";
import Layout from "../components/Layout";

const features = [
  {
    title: "Real-time Monitoring",
    description: "24/7 continuous monitoring of your network infrastructure with instant threat detection and alerting.",
    icon: <FiEye size={28} className="text-blue-500" />,
  },
  {
    title: "Threat Intelligence",
    description: "Advanced AI-powered threat analysis with machine learning algorithms for predictive security.",
    icon: <FiAlertTriangle size={28} className="text-red-500" />,
  },
  {
    title: "Analytics Dashboard",
    description: "Comprehensive security metrics and reporting with customizable dashboards and insights.",
    icon: <FiBarChart2 size={28} className="text-green-500" />,
  },
  {
    title: "Incident Response",
    description: "Automated incident response workflows with customizable playbooks and escalation procedures.",
    icon: <FiLock size={28} className="text-purple-500" />,
  },
  {
    title: "Team Collaboration",
    description: "Multi-user access controls with role-based permissions and collaborative investigation tools.",
    icon: <FiUsers size={28} className="text-orange-500" />,
  },
  {
    title: "Global Coverage",
    description: "Worldwide threat intelligence feeds with geolocation-based risk assessment and monitoring.",
    icon: <FiGlobe size={28} className="text-cyan-500" />,
  },
];

export default function Home() {
  const router = useRouter();
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  // Check login status
  useEffect(() => {
    const checkLogin = async () => {
      try {
        const res = await fetch("/api/auth/me");
        const data = await res.json();
        setIsLoggedIn(data.loggedIn);
      } catch (err) {
        setIsLoggedIn(false);
      }
    };
    checkLogin();
  }, []);

  const handleGetStarted = () => {
    if (isLoggedIn) {
      router.push("/dashboard");
    } else {
      router.push("/login");
    }
  };

  return (
    <Layout>
      <div className="bg-gray-50 min-h-[100vh] pt-24">
        {/* Hero Section */}
        <header className="flex flex-col items-center justify-center min-h-[40vh] text-center bg-white px-4 py-12 shadow-md rounded-b-2xl">
          <h1 className="text-4xl md:text-5xl font-extrabold text-gray-900 mb-4">
            Secure Your <span className="text-orange-600">Digital Infrastructure</span>
          </h1>
          <p className="text-gray-600 max-w-2xl mx-auto mb-8 text-lg md:text-xl">
            Advanced SIEM Dashboard providing real-time threat detection,
            comprehensive security monitoring, and intelligent incident response for enterprise environments.
          </p>
          <div className="flex justify-center gap-4 flex-wrap">
            <button
              onClick={handleGetStarted}
              className="bg-orange-600 text-white font-semibold py-3 px-8 rounded-lg shadow-lg hover:bg-orange-700 transition"
            >
              Get Started
            </button>
            <Link href="/about">
              <button className="border border-gray-300 text-gray-700 font-semibold py-3 px-8 rounded-lg hover:bg-gray-100 transition">
                Learn More
              </button>
            </Link>
          </div>
        </header>

        {/* Features Grid */}
        <section className="py-20">
          <div className="max-w-7xl mx-auto px-4">
            <div className="text-center mb-16">
              <h2 className="text-3xl md:text-4xl font-bold mb-4">Comprehensive Security Intelligence</h2>
              <p className="text-gray-600 max-w-2xl mx-auto text-lg">
                Protect your organization with enterprise-grade security monitoring and threat intelligence
              </p>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              {features.map((feature, index) => (
                <div
                  key={index}
                  className="bg-white rounded-2xl shadow-lg p-8 flex flex-col items-start gap-4 hover:shadow-2xl transition transform hover:-translate-y-1"
                >
                  <div className="bg-gray-100 p-4 rounded-full">{feature.icon}</div>
                  <h3 className="text-xl font-semibold text-gray-900">{feature.title}</h3>
                  <p className="text-gray-600 text-sm md:text-base">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </Layout>
  );
}
