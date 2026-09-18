import { useState } from "react";
import { AuthContext } from "./authContextValue";

const readUser = () => {
  try { return JSON.parse(sessionStorage.getItem("sentinelx_user") || "null"); } catch { return null; }
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readUser);
  const signIn = (nextUser, token) => { sessionStorage.setItem("sentinelx_token", token); sessionStorage.setItem("sentinelx_user", JSON.stringify(nextUser)); setUser(nextUser); };
  const signOut = () => { sessionStorage.removeItem("sentinelx_token"); sessionStorage.removeItem("sentinelx_user"); setUser(null); };
  return <AuthContext.Provider value={{ user, signIn, signOut, isAdmin: user?.role === "admin" }}>{children}</AuthContext.Provider>;
}
