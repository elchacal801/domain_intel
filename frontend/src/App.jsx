import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { DataProvider } from '@/context/DataContext';
import { ThemeProvider } from '@/context/ThemeContext';
import Layout from '@/components/Layout';
import MatchDashboard from '@/pages/MatchDashboard';
import InvestigateLanding from '@/pages/InvestigateLanding';
import DomainDetail from '@/pages/DomainDetail';
import DomainCompare from '@/pages/DomainCompare';
import ClusterView from '@/pages/ClusterView';
import BriefingView from '@/pages/BriefingView';

export default function App() {
  return (
    <ThemeProvider>
      <HashRouter>
        <DataProvider>
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<Navigate to="/matches" replace />} />
              <Route path="matches" element={<MatchDashboard />} />
              <Route path="investigate" element={<InvestigateLanding />} />
              <Route path="investigate/:domain" element={<DomainDetail />} />
              <Route path="compare/:domainA/:domainB" element={<DomainCompare />} />
              <Route path="clusters" element={<ClusterView />} />
              <Route path="briefing" element={<BriefingView />} />
            </Route>
          </Routes>
        </DataProvider>
      </HashRouter>
    </ThemeProvider>
  );
}
