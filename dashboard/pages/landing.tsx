"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { FiEye, FiAlertTriangle, FiBarChart2, FiMessageSquare, FiUsers, FiCheckCircle } from "react-icons/fi";
import Layout from "../components/Layout";

const features = [
  {
    title: "Real-time Threat Detection",
    description: "Monitor your network continuously with instant detection of attacks and anomalies in real time.",
    icon: <FiEye size={28} className="text-blue-500" />,
  },
  {
    title: "Full Log Scanning",
    description: "Automatically scan and analyze all system logs to detect suspicious activities across your infrastructure.",
    icon: <FiBarChart2 size={28} className="text-green-500" />,
  },
  {
    title: "AI Chatbot Guidance",
    description: "Intelligent chatbot provides actionable advice and suggestions for responding to security alerts.",
    icon: <FiMessageSquare size={28} className="text-purple-500" />,
  },
  {
    title: "Threat Intelligence & Alerts",
    description: "Receive contextual alerts with AI-powered threat intelligence to stay ahead of potential attacks.",
    icon: <FiAlertTriangle size={28} className="text-red-500" />,
  },
  {
    title: "Team Collaboration",
    description: "Work together with role-based permissions, shared investigations, and audit trails for every alert.",
    icon: <FiUsers size={28} className="text-orange-500" />,
  },
  {
    title: "Proven Results",
    description: "Trusted by enterprises for improving security posture and preventing critical breaches.",
    icon: <FiCheckCircle size={28} className="text-cyan-500" />,
  },
];

export default function Home() {
  const router = useRouter();
  const [isLoggedIn, setIsLoggedIn] = useState(false);

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
            Protect Your <span className="text-orange-600">Digital Infrastructure</span>
          </h1>
          <p className="text-gray-600 max-w-2xl mx-auto mb-8 text-lg md:text-xl">
            Our SIEM tool provides real-time threat detection, full log scanning, and AI-powered alert guidance
            to secure your organization from attacks and vulnerabilities.
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
              <h2 className="text-3xl md:text-4xl font-bold mb-4">Why Choose Our SIEM Tool</h2>
              <p className="text-gray-600 max-w-2xl mx-auto text-lg">
                From continuous monitoring to intelligent AI-driven alerts, our system keeps your organization safe and informed.
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

        {/* Success Stories */}
        <section className="py-20 bg-gray-100">
          <div className="max-w-7xl mx-auto px-4 text-center">
            <h2 className="text-3xl md:text-4xl font-bold mb-12">Proven Success</h2>
            <div className="grid md:grid-cols-3 gap-8">
              <div className="bg-white rounded-2xl shadow-lg p-8 hover:shadow-2xl transition">
                <h3 className="text-2xl font-bold text-orange-600 mb-2">500+</h3>
                <p className="text-gray-600">Alerts resolved automatically by the system per month.</p>
              </div>
              <div className="bg-white rounded-2xl shadow-lg p-8 hover:shadow-2xl transition">
                <h3 className="text-2xl font-bold text-orange-600 mb-2">99%</h3>
                <p className="text-gray-600">Detection accuracy of suspicious activities across all logs.</p>
              </div>
              <div className="bg-white rounded-2xl shadow-lg p-8 hover:shadow-2xl transition">
                <h3 className="text-2xl font-bold text-orange-600 mb-2">24/7</h3>
                <p className="text-gray-600">Continuous monitoring with real-time AI assistance for incident response.</p>
              </div>
            </div>
          </div>
        </section>
      </div>
    </Layout>
  );
}
