import React, { useState } from "react";

const ResetPassword = () => {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      setMessage("");
      return;
    }
    setError("");
    setMessage("Password has been reset successfully!");
  };

  return (
    <form onSubmit={handleSubmit} className="p-4 bg-white shadow-md rounded">
      <h2 className="text-xl font-bold mb-4 font-poppins italic">Reset Password</h2>
      <input
        type="password"
        placeholder="Enter new password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="w-full p-2 border rounded mb-4"
        required
      />
      <input
        type="password"
        placeholder="Confirm new password"
        value={confirmPassword}
        onChange={(e) => setConfirmPassword(e.target.value)}
        className="w-full p-2 border rounded mb-4"
        required
      />
      {error && <p className="text-red-500 mb-4">{error}</p>}
      {message && <p className="text-green-500 mb-4">{message}</p>}
      <button
        type="submit"
        className="w-full py-2 px-4 bg-blue-500 text-white rounded hover:bg-blue-600 font-poppins italic"
      >
        Reset Password
      </button>
    </form>
  );
};

export default ResetPassword;
