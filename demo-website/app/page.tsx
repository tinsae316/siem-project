import styles from "./page.module.css";

export default function Home() {
  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <h1 className={styles.title}>SIEM Log Analysis Demo</h1>

        <p className={styles.description}>
          Explore your security logs in real-time and gain actionable insights.
        </p>

        <section className={styles.features}>
          <h2>Features</h2>
          <ol>
            <li>Collect logs from multiple sources (firewalls, servers, applications).</li>
            <li>Analyze and correlate events to detect anomalies.</li>
            <li>Visualize trends with interactive dashboards.</li>
            <li>Set alerts for suspicious activity.</li>
          </ol>
        </section>

         
      </main>

       
    </div>
  );
}
