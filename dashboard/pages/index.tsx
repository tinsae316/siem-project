export const getServerSideProps = async () => {
  return {
    redirect: {
      destination: "/landing",
      permanent: false,
    },
  };
};

export default function Index() {
  return null;
}


