import React from "react";
import ForgetPassword from "../components/ForgetPassword";

const Home = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <h1 className="mb-4 text-4xl italic font-extrabold text-blue-700 font-poppins">
        Password Reset Task
      </h1>
      <ForgetPassword />
    </div>
  );
};

export default Home;