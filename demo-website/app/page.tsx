import Image from "next/image";
import styles from "./page.module.css";

export default function Home() {
  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <h1 style={{ textAlign: "center", marginBottom: 16 }}>
          Welcome to the Security Demo Site
        </h1>
        <p style={{ textAlign: "center", maxWidth: 600, margin: "0 auto 32px" }}>
          This is a demo website built to showcase simple web attacks such as XSS, 
          SQL Injection, and other security vulnerabilities in a safe environment.
        </p>

        <div style={{ display: "flex", justifyContent: "center", gap: 24, marginBottom: 40 }}>
          <a className={styles.primary} href="/login">
            Login
          </a>
          <a className={styles.secondary} href="/search">
            Try XSS Demo
          </a>
        </div>
      </main>
    </div>
  );
}
