import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { AccountPage } from "./pages/Account";
import { EnrollPage, LoginPage, MFAPage, SetupPage } from "./pages/AuthPages";
import { DeploymentPage } from "./pages/Deployment";
import { GitCallbackPage } from "./pages/GitCallback";
import { NewProjectPage } from "./pages/NewProject";
import { ProjectPage } from "./pages/Project";
import { ProjectsPage } from "./pages/Projects";
import { PlatformPage } from "./pages/Platform";

export default function App() {
  const { state } = useAuth();
  switch (state.phase) {
    case "loading":
      return <Loading />;
    case "bootstrap":
      return <SetupPage />;
    case "anonymous":
      return <LoginPage />;
    case "mfa":
      return <MFAPage session={state.session} />;
    case "enroll":
      return <EnrollPage />;
  }
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<ProjectsPage />} />
        <Route path="new" element={<NewProjectPage />} />
        <Route path="projects/:id/*" element={<ProjectPage />} />
        <Route path="deployments/:id" element={<DeploymentPage />} />
        <Route path="settings/git/callback" element={<GitCallbackPage />} />
        <Route path="settings/*" element={<PlatformPage />} />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
