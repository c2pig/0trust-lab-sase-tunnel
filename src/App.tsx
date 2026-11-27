import React from 'react';
import { LabLeaseGuard } from './shell';
import { SaseTunnelPage } from './pages/SaseTunnelPage';

export default function App(): React.ReactElement {
  return (
    <LabLeaseGuard labSlug="sase-tunnel" labTitle="Zero-Trust SASE & Browser-to-Origin Tunnel">
      <SaseTunnelPage
        onBack={() => {
          window.location.href =
            window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
              ? 'http://localhost:5173/'
              : 'https://0trust.dev/';
        }}
      />
    </LabLeaseGuard>
  );
}
