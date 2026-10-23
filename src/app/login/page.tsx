import type { Metadata } from "next";
import LoginScreen from "@/components/LoginScreen";

export const metadata: Metadata = {
  title: "Sign in — Lumen",
  description: "Securely sign in to your Lumen gateway workspace.",
};

export default function LoginPage() {
  return <LoginScreen />;
}
