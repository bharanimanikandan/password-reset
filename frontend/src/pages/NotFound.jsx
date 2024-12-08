import React from "react";
import { Link } from "react-router-dom";

const NotFound = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <h1 className="text-4xl font-bold text-red-500 font-poppins italic">404 - Page Not Found</h1>
      <p className="mt-4 text-lg text-gray-600 font-poppins italic">
        Oops! The page you're looking for doesn't exist.
      </p>
      <Link
        to="/"
        className="px-6 py-3 mt-6 bg-blue-500 text-white rounded shadow hover:bg-blue-600 font-poppins italic"
      >
        Go Back Home
      </Link>
    </div>
  );
};

export default NotFound;