import type { Metadata } from "next";
import ProfileScreen from "@/components/ProfileScreen";

export const metadata: Metadata = {
  title: "Your profile — Lumen",
  description: "Manage your Lumen workspace identity.",
};

export default function ProfilePage() {
  return <ProfileScreen />;
}
