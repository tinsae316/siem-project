// pages/learn-more.tsx
import { FiShield, FiCpu, FiBarChart2, FiAlertTriangle, FiUsers, FiCloud } from "react-icons/fi";
import Link from "next/link";
import Layout from "../components/Layout";

export default function LearnMore() {
  return (
    <Layout>
      <div className="bg-gray-50 min-h-screen text-gray-800">
        {/* Hero Section */}
        <section className="text-center py-8 min-h-[30] bg-white">
          <h1 className="text-4xl md:text-5xl font-bold mb-4">
            Powering the Future of <span className="text-orange-600">Cyber Defense</span>
          </h1>
          <p className="max-w-3xl mx-auto text-gray-600">
            Our SIEM platform combines real-time monitoring, AI-driven analytics, and automated response to protect your
            entire digital ecosystem — from endpoints to cloud.
          </p>
        </section>

        {/* Capabilities Section */}
        <section className="py-10 max-w-7xl mx-auto px-3">
          <h2 className="text-3xl font-bold text-center mb-12">Core Capabilities</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-10">
            {[
              {
                icon: <FiShield className="text-orange-600" size={28} />,
                title: "Centralized Threat Detection",
                desc: "Monitor all network activity through a unified dashboard with real-time alerting and anomaly detection.",
              },
              {
                icon: <FiCpu className="text-blue-500" size={28} />,
                title: "AI-Powered Correlation",
                desc: "Leverage machine learning models to correlate events, detect advanced persistent threats, and reduce false positives.",
              },
              {
                icon: <FiBarChart2 className="text-green-600" size={28} />,
                title: "Advanced Analytics",
                desc: "Gain insights with visual reports and custom dashboards showing attack trends, vulnerabilities, and response metrics.",
              },
              {
                icon: <FiAlertTriangle className="text-red-500" size={28} />,
                title: "Automated Incident Response",
                desc: "Trigger playbooks that isolate compromised hosts, notify stakeholders, and initiate forensic logging instantly.",
              },
              {
                icon: <FiUsers className="text-purple-500" size={28} />,
                title: "Role-Based Access Control",
                desc: "Empower your security team with tiered permissions, collaboration tools, and audit-ready logging.",
              },
              {
                icon: <FiCloud className="text-cyan-600" size={28} />,
                title: "Cloud & On-Prem Integration",
                desc: "Seamlessly connect AWS, Azure, and on-prem assets to unify threat visibility across hybrid infrastructures.",
              },
            ].map((item, idx) => (
              <div
                key={idx}
                className="bg-white p-6 rounded-xl shadow hover:shadow-lg transition flex flex-col gap-3"
              >
                <div>{item.icon}</div>
                <h3 className="font-semibold text-lg">{item.title}</h3>
                <p className="text-gray-600 text-sm">{item.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Architecture Overview */}
        <section className="bg-gray-100 py-8">
          <div className="max-w-6xl mx-auto px-6 text-center">
            <h2 className="text-3xl font-bold mb-8">How It Works</h2>
            <p className="max-w-3xl mx-auto text-gray-600 mb-12">
              The SIEM engine ingests logs and events from multiple sources — firewalls, endpoints, cloud APIs, and IoT
              devices. It correlates this data in real time, applies AI-based threat models, and generates actionable
              alerts that flow directly to your dashboard.
            </p>
            </div>
        </section>

        {/* Use Cases Section */}
        <section className="py-20 max-w-6xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-center mb-12">Real-World Use Cases</h2>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                title: "Enterprise SOC",
                desc: "Monitor thousands of assets, streamline investigations, and automate escalation workflows.",
              },
              {
                title: "Cloud Security",
                desc: "Detect misconfigurations and intrusion attempts in AWS or Azure environments in real time.",
              },
              {
                title: "Compliance & Audit",
                desc: "Generate on-demand audit logs to meet standards like ISO 27001, SOC2, and GDPR.",
              },
            ].map((usecase, idx) => (
              <div
                key={idx}
                className="bg-white p-6 rounded-xl shadow hover:shadow-lg transition flex flex-col gap-2"
              >
                <h3 className="font-semibold text-lg">{usecase.title}</h3>
                <p className="text-gray-600 text-sm">{usecase.desc}</p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </Layout>
  );
}