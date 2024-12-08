import React, { useState } from 'react';
import axios from 'axios';

const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post("http://localhost:5000/auth/forgot-password", { email });
    //   These line for display success messages
      setMessage(response.data.message);
    } catch (error) {
      setMessage(error.response?.data?.message || "An error occurred");
    }
  };

  return (
    <div className="flex ">
      <div className="w-full max-w-md p-8 mx-4 overflow-hidden outline-dotted bg-slate-200 rounded-lg shadow-2xl">
        <h2 className="mb-8 text-3xl font-bold text-center text-transparent text-gray-800 font-poppins bg-clip-text bg-gradient-to-r from-orange-500 to-red-500">
          Forgot Password
        </h2>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="relative">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              className="w-full p-2 text-lg placeholder-gray-400 transition-all duration-300 ease-in-out transform border-2 border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
              required
            />
            <div className="absolute text-lg text-gray-400 left-4 top-3">
              <i className="fas fa-envelope"></i>
            </div>
          </div>
          <button
            type="submit"
            className="w-full p-4 text-lg font-medium text-white transition-all duration-300 ease-in-out rounded-md bg-gradient-to-r from-indigo-500 to-purple-500 hover:bg-gradient-to-r hover:from-purple-600 hover:to-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            Submit
          </button>
        </form>
        {message && (
          <p className="mt-4 text-sm text-center text-gray-700">
            {message}
          </p>
        )}
      </div>
    </div>
  );
};

export default ForgotPassword;