import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Overview } from "./pages/Overview";
import { Placeholder } from "./pages/Placeholder";
import { Notifications } from "./pages/Notifications";
import { Services } from "./pages/Services";
import { Incidents } from "./pages/Incidents";
import { IncidentDetail } from "./pages/IncidentDetail";
import { RecoveryHistory } from "./pages/RecoveryHistory";
import { Escalations } from "./pages/Escalations";
import { DemoControl } from "./pages/DemoControl";
import { Settings } from "./pages/Settings";
import "./styles.css";

export default function App() {
  return <BrowserRouter><Layout><Routes>
    <Route path="/" element={<Overview />} />
    <Route path="/incidents" element={<Incidents />} />
    <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
    <Route path="/services" element={<Services />} />
    <Route path="/recovery" element={<RecoveryHistory />} />
    <Route path="/notifications" element={<Notifications />} />
    <Route path="/demo" element={<DemoControl />} />
    <Route path="/escalations" element={<Escalations />} />
    <Route path="/settings" element={<Settings />} />
    <Route path="*" element={<Placeholder title="Page not found" description="The requested workspace view does not exist." />} />
  </Routes></Layout></BrowserRouter>;
}
