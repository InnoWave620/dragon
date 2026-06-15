import React, { useState } from 'react';
import { 
  Plus, 
  Search, 
  Trash2, 
  Globe, 
  Terminal, 
  Folder, 
  Cpu, 
  Layers,
  X 
} from 'lucide-react';

interface Asset {
  id: string;
  name: string;
  target: string;
  type: 'website' | 'localhost' | 'folder' | 'api' | 'docker';
  environment: 'production' | 'staging' | 'development';
  owner: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  createdAt: string;
}

interface AssetManagerProps {
  assets: Asset[];
  onRefresh: () => void;
}

export default function AssetManager({ assets, onRefresh }: AssetManagerProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Form states
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [type, setType] = useState<'website' | 'localhost' | 'folder' | 'api' | 'docker'>('website');
  const [environment, setEnvironment] = useState<'production' | 'staging' | 'development'>('development');
  const [owner, setOwner] = useState('');
  const [criticality, setCriticality] = useState<'critical' | 'high' | 'medium' | 'low'>('medium');

  const handleAddAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !target) return;

    try {
      await window.electronAPI.db.addAsset({
        name,
        target,
        type,
        environment,
        owner: owner || 'SecOps Team',
        criticality
      });
      
      // Reset form
      setName('');
      setTarget('');
      setType('website');
      setEnvironment('development');
      setOwner('');
      setCriticality('medium');
      setIsModalOpen(false);
      onRefresh();
    } catch (err) {
      console.error('Failed to save asset:', err);
    }
  };

  const handleDeleteAsset = async (id: string) => {
    const isConfirmed = await window.electronAPI.dialog.confirm(
      'Are you sure you want to delete this asset? This will remove all associated scan findings.'
    );
    if (isConfirmed) {
      try {
        await window.electronAPI.db.deleteAsset(id);
        onRefresh();
      } catch (err) {
        console.error('Failed to delete asset:', err);
      }
    }
  };

  const getAssetIcon = (type: string) => {
    switch (type) {
      case 'website': return <Globe className="w-4 h-4 text-cyber-cyan" />;
      case 'localhost': return <Terminal className="w-4 h-4 text-cyber-emerald" />;
      case 'folder': return <Folder className="w-4 h-4 text-cyber-amber" />;
      case 'api': return <Layers className="w-4 h-4 text-cyber-purple" />;
      default: return <Cpu className="w-4 h-4 text-cyber-blue" />;
    }
  };

  const getCriticalityBadge = (level: string) => {
    switch (level) {
      case 'critical': return <span className="badge-critical text-[10px]">Critical</span>;
      case 'high': return <span className="badge-high text-[10px]">High</span>;
      case 'medium': return <span className="badge-medium text-[10px]">Medium</span>;
      default: return <span className="badge-low text-[10px]">Low</span>;
    }
  };

  const filteredAssets = assets.filter(asset => {
    const matchesSearch = asset.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          asset.target.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = selectedType === 'all' || asset.type === selectedType;
    return matchesSearch && matchesType;
  });

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-wide">Asset Inventory</h2>
          <p className="text-sm text-gray-500">Register and audit networks, endpoints, containers, and repositories.</p>
        </div>
        <button 
          onClick={() => setIsModalOpen(true)}
          className="btn-cyber-cyan flex items-center space-x-2 text-sm"
        >
          <Plus className="w-4 h-4" />
          <span>Add Asset</span>
        </button>
      </div>

      {/* FILTER & SEARCH BAR */}
      <div className="flex flex-col sm:flex-row gap-4">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-3.5" />
          <input 
            type="text" 
            placeholder="Search assets by name or target..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input-cyber pl-10"
          />
        </div>
        {/* Type select */}
        <div className="w-48">
          <select 
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="input-cyber"
          >
            <option value="all">All Types</option>
            <option value="website">Websites</option>
            <option value="localhost">Localhost Apps</option>
            <option value="folder">Local Folders</option>
            <option value="api">APIs</option>
            <option value="docker">Docker Containers</option>
          </select>
        </div>
      </div>

      {/* ASSET DATA TABLE */}
      <div className="glass-card overflow-hidden">
        {filteredAssets.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-dark-surface border-b border-dark-border text-gray-500 font-bold uppercase tracking-wider">
                  <th className="p-4 w-12">Type</th>
                  <th className="p-4">Asset Name</th>
                  <th className="p-4">Target Endpoint/Directory</th>
                  <th className="p-4">Environment</th>
                  <th className="p-4">Criticality</th>
                  <th className="p-4">Owner</th>
                  <th className="p-4 w-12 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-border/50">
                {filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-dark-surface/40 transition-colors">
                    <td className="p-4 text-center">
                      <div className="p-1.5 bg-dark-bg border border-dark-border rounded-lg inline-block">
                        {getAssetIcon(asset.type)}
                      </div>
                    </td>
                    <td className="p-4 font-semibold text-white">{asset.name}</td>
                    <td className="p-4 font-mono text-cyber-cyan truncate max-w-xs">{asset.target}</td>
                    <td className="p-4">
                      <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 font-bold uppercase text-[10px]">
                        {asset.environment}
                      </span>
                    </td>
                    <td className="p-4">{getCriticalityBadge(asset.criticality)}</td>
                    <td className="p-4 text-gray-400 font-medium">{asset.owner}</td>
                    <td className="p-4 text-center">
                      <button 
                        onClick={() => handleDeleteAsset(asset.id)}
                        className="p-1.5 hover:bg-cyber-rose/10 text-gray-500 hover:text-cyber-rose border border-transparent hover:border-cyber-rose/30 rounded-lg transition-all"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <Globe className="w-12 h-12 mx-auto mb-3 opacity-30 text-cyber-cyan" />
            <p className="text-sm">No assets registered yet.</p>
            <p className="text-xs text-gray-600 mt-1">Click the "Add Asset" button to specify your scanning scope.</p>
          </div>
        )}
      </div>

      {/* ADD ASSET MODAL DIALOG */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="glass-card w-full max-w-lg shadow-2xl relative">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-dark-border">
              <h3 className="text-lg font-bold text-white">Register Scope Asset</h3>
              <button 
                onClick={() => setIsModalOpen(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleAddAsset} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                {/* Asset Name */}
                <div className="space-y-1">
                  <label className="text-xs text-gray-500 font-semibold uppercase">Asset Name</label>
                  <input 
                    type="text" 
                    required 
                    placeholder="e.g. My Website API" 
                    value={name} 
                    onChange={e => setName(e.target.value)}
                    className="input-cyber text-sm"
                  />
                </div>
                {/* Asset Type */}
                <div className="space-y-1">
                  <label className="text-xs text-gray-500 font-semibold uppercase">Asset Type</label>
                  <select 
                    value={type} 
                    onChange={e => setType(e.target.value as any)}
                    className="input-cyber text-sm"
                  >
                    <option value="website">Website (Remote URL)</option>
                    <option value="localhost">Localhost Port / App</option>
                    <option value="folder">Local Source Folder</option>
                    <option value="api">REST/GraphQL API</option>
                    <option value="docker">Docker Container</option>
                  </select>
                </div>
              </div>

              {/* Target Scope */}
              <div className="space-y-1">
                <label className="text-xs text-gray-500 font-semibold uppercase">
                  Target Endpoint / Local Directory Path
                </label>
                <input 
                  type="text" 
                  required 
                  placeholder={
                    type === 'folder' 
                      ? 'e.g. C:\\Users\\Dell\\Projects\\my-react-app' 
                      : type === 'website' 
                        ? 'e.g. https://example.com' 
                        : 'e.g. http://localhost:8080'
                  }
                  value={target} 
                  onChange={e => setTarget(e.target.value)}
                  className="input-cyber font-mono text-sm"
                />
                <p className="text-[10px] text-gray-600">
                  Provide either a full absolute path for local directories or a valid URL/URI for servers.
                </p>
              </div>

              <div className="grid grid-cols-3 gap-4">
                {/* Environment */}
                <div className="space-y-1">
                  <label className="text-xs text-gray-500 font-semibold uppercase">Environment</label>
                  <select 
                    value={environment} 
                    onChange={e => setEnvironment(e.target.value as any)}
                    className="input-cyber text-sm"
                  >
                    <option value="development">Dev</option>
                    <option value="staging">Staging</option>
                    <option value="production">Prod</option>
                  </select>
                </div>
                {/* Criticality */}
                <div className="space-y-1">
                  <label className="text-xs text-gray-500 font-semibold uppercase">Business Criticality</label>
                  <select 
                    value={criticality} 
                    onChange={e => setCriticality(e.target.value as any)}
                    className="input-cyber text-sm"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                {/* Owner */}
                <div className="space-y-1">
                  <label className="text-xs text-gray-500 font-semibold uppercase">Owner/Assigned Team</label>
                  <input 
                    type="text" 
                    placeholder="e.g. Dev Team A" 
                    value={owner} 
                    onChange={e => setOwner(e.target.value)}
                    className="input-cyber text-sm"
                  />
                </div>
              </div>

              {/* Form buttons */}
              <div className="flex items-center justify-end space-x-3 pt-4 border-t border-dark-border">
                <button 
                  type="button" 
                  onClick={() => setIsModalOpen(false)}
                  className="btn-cyber-gray text-sm py-1.5"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="btn-cyber-cyan text-sm py-1.5"
                >
                  Save Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
