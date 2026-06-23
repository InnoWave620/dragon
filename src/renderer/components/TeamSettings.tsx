import React, { useState, useEffect } from 'react';
import { 
  Plus, 
  Trash2, 
  User, 
  Mail, 
  Briefcase, 
  ShieldAlert,
  Search
} from 'lucide-react';

interface Developer {
  id: string;
  name: string;
  email: string;
  role?: string;
  createdAt: string;
}

interface TeamSettingsProps {
  onRefresh: () => void;
}

export default function TeamSettings({ onRefresh }: TeamSettingsProps) {
  const [developers, setDevelopers] = useState<Developer[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Form states
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('Vulnerability Analyst');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchDevelopers = async () => {
    try {
      const devs = await window.electronAPI.db.getDevelopers();
      setDevelopers(devs || []);
    } catch (err) {
      console.error('Failed to load developers:', err);
    }
  };

  useEffect(() => {
    fetchDevelopers();
  }, []);

  const handleAddDeveloper = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!name.trim()) {
      setErrorMsg('Name is required.');
      return;
    }
    if (!email.trim() || !email.includes('@')) {
      setErrorMsg('Please enter a valid email address.');
      return;
    }

    // Check duplicate email locally first
    const duplicate = developers.find(d => d.email.toLowerCase() === email.trim().toLowerCase());
    if (duplicate) {
      setErrorMsg('A developer with this email already exists.');
      return;
    }

    try {
      await window.electronAPI.db.addDeveloper({
        name: name.trim(),
        email: email.trim(),
        role: role
      });
      
      // Reset Form
      setName('');
      setEmail('');
      setRole('Vulnerability Analyst');
      setErrorMsg(null);
      
      // Refresh local & parent states
      await fetchDevelopers();
      onRefresh();
    } catch (err: any) {
      console.error('Failed to save developer:', err);
      setErrorMsg(err.message || 'Failed to save developer.');
    }
  };

  const handleDeleteDeveloper = async (id: string, devName: string) => {
    const isConfirmed = await window.electronAPI.dialog.confirm(
      `Are you sure you want to remove ${devName} from the developer registry? This will unassign them from any findings.`
    );
    
    if (isConfirmed) {
      try {
        await window.electronAPI.db.deleteDeveloper(id);
        await fetchDevelopers();
        onRefresh();
      } catch (err) {
        console.error('Failed to delete developer:', err);
      }
    }
  };

  const filteredDevs = developers.filter(d => 
    d.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    d.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (d.role && d.role.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Developer Registry</h2>
        <p className="text-gray-400 text-sm mt-1">Manage team members and developers available for vulnerability assignment.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Side: Register Developer Form */}
        <div className="lg:col-span-1">
          <div className="glass-card p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center space-x-2 pb-2 border-b border-dark-border">
              <User className="w-5 h-5 text-cyber-cyan" />
              <span>Register Developer</span>
            </h3>

            {errorMsg && (
              <div className="p-3 bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose text-xs rounded-lg flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleAddDeveloper} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs text-gray-400 font-semibold uppercase tracking-wider">Full Name</label>
                <div className="relative">
                  <User className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Doe"
                    className="input-cyber pl-10"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-gray-400 font-semibold uppercase tracking-wider">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="jane.doe@company.local"
                    className="input-cyber pl-10"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-gray-400 font-semibold uppercase tracking-wider">Role</label>
                <div className="relative">
                  <Briefcase className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="input-cyber pl-10 appearance-none bg-dark-surface"
                  >
                    <option value="Senior Security Engineer">Senior Security Engineer</option>
                    <option value="Security Analyst">Security Analyst</option>
                    <option value="Vulnerability Analyst">Vulnerability Analyst</option>
                    <option value="DevSecOps Engineer">DevSecOps Engineer</option>
                    <option value="Lead Developer">Lead Developer</option>
                    <option value="Backend Developer">Backend Developer</option>
                    <option value="Frontend Developer">Frontend Developer</option>
                  </select>
                </div>
              </div>

              <button
                type="submit"
                className="w-full btn-cyber-cyan flex items-center justify-center space-x-2 mt-2"
              >
                <Plus className="w-4 h-4" />
                <span>Add Member</span>
              </button>
            </form>
          </div>
        </div>

        {/* Right Side: Developers List */}
        <div className="lg:col-span-2 space-y-4">
          
          {/* Search bar */}
          <div className="flex items-center space-x-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by name, email or role..."
                className="input-cyber pl-10 bg-dark-surface/40"
              />
            </div>
          </div>

          {/* Cards Grid */}
          {filteredDevs.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredDevs.map((dev) => (
                <div key={dev.id} className="glass-card glass-card-hover p-5 flex items-start justify-between space-x-4">
                  <div className="space-y-2 flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <div className="w-8 h-8 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/20 flex items-center justify-center text-cyber-cyan text-sm font-bold uppercase shrink-0">
                        {dev.name.split(' ').map(n => n[0]).join('').substring(0, 2)}
                      </div>
                      <div className="min-w-0">
                        <h4 className="font-bold text-white truncate text-sm" title={dev.name}>{dev.name}</h4>
                        <span className="text-[10px] text-cyber-cyan/90 font-medium px-2 py-0.5 bg-cyber-cyan/5 border border-cyber-cyan/15 rounded">
                          {dev.role || 'Developer'}
                        </span>
                      </div>
                    </div>
                    
                    <div className="text-xs text-gray-400 flex items-center space-x-1.5 pt-1 pl-0.5 truncate">
                      <Mail className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                      <span className="truncate" title={dev.email}>{dev.email}</span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleDeleteDeveloper(dev.id, dev.name)}
                    className="p-1.5 rounded-lg border border-dark-border text-gray-500 hover:text-cyber-rose hover:border-cyber-rose/40 hover:bg-cyber-rose/5 transition-colors shrink-0"
                    title="Remove Developer"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="glass-card p-12 text-center text-gray-500 flex flex-col items-center justify-center space-y-3">
              <User className="w-12 h-12 text-gray-600 animate-pulse" />
              <div className="space-y-1">
                <p className="font-bold text-gray-400">No Developers Registered</p>
                <p className="text-xs">Add security personnel and developers to assign issues to them.</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
