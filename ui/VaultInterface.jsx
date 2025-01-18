import React, { useState } from 'react';
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";

const VaultInterface = () => {
  const [credentials, setCredentials] = useState({
    clientId: '',
    clientSecret: '',
    tenantId: '',
    vaultName: '',
  });
  
  const [selectedOperation, setSelectedOperation] = useState('list');
  const [operationParams, setOperationParams] = useState({
    secretName: '',
    secretValue: '',
  });
  
  const [status, setStatus] = useState({
    loading: false,
    message: '',
    error: false,
  });

  const handleCredentialChange = (field, value) => {
    setCredentials(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleOperationParamChange = (field, value) => {
    setOperationParams(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const executeOperation = async () => {
    setStatus({ loading: true, message: '', error: false });
    
    // In real implementation, this would call your Zig backend
    try {
      setStatus({
        loading: false,
        message: 'Operation completed successfully',
        error: false
      });
    } catch (error) {
      setStatus({
        loading: false,
        message: error.message,
        error: true
      });
    }
  };

  return (
    <div className="container mx-auto p-4 max-w-2xl">
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Azure Key Vault Manager</CardTitle>
          <CardDescription>Manage your Azure Key Vault secrets securely</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Client ID</label>
              <Input
                type="text"
                value={credentials.clientId}
                onChange={(e) => handleCredentialChange('clientId', e.target.value)}
                placeholder="Enter Client ID"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Client Secret</label>
              <Input
                type="password"
                value={credentials.clientSecret}
                onChange={(e) => handleCredentialChange('clientSecret', e.target.value)}
                placeholder="Enter Client Secret"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Tenant ID</label>
              <Input
                type="text"
                value={credentials.tenantId}
                onChange={(e) => handleCredentialChange('tenantId', e.target.value)}
                placeholder="Enter Tenant ID"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Vault Name</label>
              <Input
                type="text"
                value={credentials.vaultName}
                onChange={(e) => handleCredentialChange('vaultName', e.target.value)}
                placeholder="Enter Vault Name"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="pt-6">
          <Tabs defaultValue="list" onValueChange={setSelectedOperation}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="list">List Secrets</TabsTrigger>
              <TabsTrigger value="get">Get Secret</TabsTrigger>
              <TabsTrigger value="set">Set Secret</TabsTrigger>
            </TabsList>
            
            <TabsContent value="list" className="mt-4">
              <Button 
                className="w-full"
                onClick={executeOperation}
                disabled={status.loading}
              >
                List All Secrets
              </Button>
            </TabsContent>

            <TabsContent value="get" className="mt-4 space-y-4">
              <Input
                type="text"
                placeholder="Secret Name"
                value={operationParams.secretName}
                onChange={(e) => handleOperationParamChange('secretName', e.target.value)}
              />
              <Button 
                className="w-full"
                onClick={executeOperation}
                disabled={status.loading}
              >
                Get Secret
              </Button>
            </TabsContent>

            <TabsContent value="set" className="mt-4 space-y-4">
              <Input
                type="text"
                placeholder="Secret Name"
                value={operationParams.secretName}
                onChange={(e) => handleOperationParamChange('secretName', e.target.value)}
              />
              <Input
                type="text"
                placeholder="Secret Value"
                value={operationParams.secretValue}
                onChange={(e) => handleOperationParamChange('secretValue', e.target.value)}
              />
              <Button 
                className="w-full"
                onClick={executeOperation}
                disabled={status.loading}
              >
                Set Secret
              </Button>
            </TabsContent>
          </Tabs>

          {status.message && (
            <Alert className="mt-4" variant={status.error ? "destructive" : "default"}>
              <AlertDescription>
                {status.message}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default VaultInterface;