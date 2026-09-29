/**
 * IndraMesh Cryptographic Topology Graph Engine
 * High-performance 2D Canvas force-directed graph visualizer with drag, zoom, pan,
 * glowing risk tiers, and node inspection.
 */
class TopologyVisualizer {
  constructor(canvasId, containerId) {
    this.canvas = document.getElementById(canvasId);
    this.container = document.getElementById(containerId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    this.nodes = [];
    this.links = [];
    this.nodeMap = new Map();
    
    this.transform = { x: 0, y: 0, k: 1 };
    this.isDragging = false;
    this.draggedNode = null;
    this.hoveredNode = null;
    this.lastMouse = { x: 0, y: 0 };
    
    this.animId = null;
    this.initEvents();
    this.resize();
  }

  resize() {
    if (!this.canvas || !this.container) return;
    const rect = this.container.getBoundingClientRect();
    const oldW = this.width || 0;
    const oldH = this.height || 0;
    this.width = rect.width;
    this.height = rect.height;
    
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    if (this.nodes.length && (oldW < 100 || oldH < 100) && this.width > 200) {
      const cx = this.width / 2;
      const cy = this.height / 2;
      this.nodes.forEach((n, idx) => {
        const angle = (idx / this.nodes.length) * Math.PI * 2;
        const rad = Math.min(this.width, this.height) * 0.3;
        n.x = cx + Math.cos(angle) * rad;
        n.y = cy + Math.sin(angle) * rad;
      });
      this.startSimulation();
    }
    this.render();
  }

  setData(data) {
    if (!data || !data.nodes) return;
    this.nodeMap.clear();
    
    // Initial circular positioning
    const cx = this.width / 2;
    const cy = this.height / 2;
    const total = data.nodes.length;
    
    this.nodes = data.nodes.map((n, i) => {
      const angle = (i / total) * 2 * Math.PI;
      const radius = n.type === 'root' ? 0 : (n.type === 'file' ? 140 : 250);
      const node = {
        ...n,
        x: cx + radius * Math.cos(angle) + (Math.random() - 0.5) * 40,
        y: cy + radius * Math.sin(angle) + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
        radius: n.size ? n.size / 2 : 10
      };
      this.nodeMap.set(n.id, node);
      return node;
    });

    this.links = (data.links || []).map(l => ({
      ...l,
      sourceNode: this.nodeMap.get(l.source),
      targetNode: this.nodeMap.get(l.target)
    })).filter(l => l.sourceNode && l.targetNode);

    this.startSimulation();
  }

  startSimulation() {
    let ticks = 0;
    const maxTicks = 180;
    
    const simulate = () => {
      if (ticks < maxTicks || this.draggedNode) {
        this.stepPhysics();
        ticks++;
      }
      this.render();
      this.animId = requestAnimationFrame(simulate);
    };
    
    if (this.animId) cancelAnimationFrame(this.animId);
    this.animId = requestAnimationFrame(simulate);
  }

  stepPhysics() {
    const kRepel = 1200;
    const kSpring = 0.04;
    const kCenter = 0.005;
    const damping = 0.85;
    const cx = this.width / 2;
    const cy = this.height / 2;

    // Repulsion between nodes
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const distSq = dx * dx + dy * dy + 100;
        const dist = Math.sqrt(distSq);
        const force = kRepel / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        if (n1 !== this.draggedNode) {
          n1.vx -= fx;
          n1.vy -= fy;
        }
        if (n2 !== this.draggedNode) {
          n2.vx += fx;
          n2.vy += fy;
        }
      }
      
      // Pull to center
      if (n1 !== this.draggedNode) {
        n1.vx += (cx - n1.x) * kCenter;
        n1.vy += (cy - n1.y) * kCenter;
      }
    }

    // Spring forces on links
    for (const link of this.links) {
      const s = link.sourceNode;
      const t = link.targetNode;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const targetDist = link.type === 'contains' ? 100 : 130;
      const force = (dist - targetDist) * kSpring;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (s !== this.draggedNode) {
        s.vx += fx;
        s.vy += fy;
      }
      if (t !== this.draggedNode) {
        t.vx -= fx;
        t.vy -= fy;
      }
    }

    // Update positions
    for (const n of this.nodes) {
      if (n === this.draggedNode) continue;
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
    }
  }

  render() {
    if (!this.ctx) return;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    ctx.save();
    ctx.translate(this.transform.x, this.transform.y);
    ctx.scale(this.transform.k, this.transform.k);

    // Draw links
    for (const link of this.links) {
      const s = link.sourceNode;
      const t = link.targetNode;
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(t.x, t.y);
      ctx.strokeStyle = link.color || 'rgba(100, 116, 139, 0.35)';
      ctx.lineWidth = link.type === 'migrates_to' ? 2 : 1;
      if (link.type === 'library') {
        ctx.setLineDash([4, 4]);
      } else {
        ctx.setLineDash([]);
      }
      ctx.stroke();
    }

    // Draw nodes
    for (const n of this.nodes) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
      
      // Node glow for critical or hovered
      if (n.tier === 'CRITICAL' || n === this.hoveredNode) {
        ctx.shadowColor = n.color || '#10B981';
        ctx.shadowBlur = 12;
      } else {
        ctx.shadowBlur = 0;
      }

      ctx.fillStyle = n.color || '#10B981';
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = '#FFFFFF';
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Draw label
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.fillStyle = n === this.hoveredNode ? '#10B981' : '#CBD5E1';
      ctx.textAlign = 'center';
      ctx.fillText(n.label || n.name || '', n.x, n.y + n.radius + 12);
    }

    ctx.restore();
  }

  initEvents() {
    if (!this.canvas) return;
    
    window.addEventListener('resize', () => this.resize());

    this.canvas.addEventListener('mousedown', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      
      const worldX = (mx - this.transform.x) / this.transform.k;
      const worldY = (my - this.transform.y) / this.transform.k;
      
      const clicked = this.findNode(worldX, worldY);
      if (clicked) {
        this.draggedNode = clicked;
        if (window.onTopologyNodeClick) {
          window.onTopologyNodeClick(clicked);
        }
      } else {
        this.isDragging = true;
      }
      this.lastMouse = { x: mx, y: my };
    });

    window.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      if (this.draggedNode) {
        this.draggedNode.x = (mx - this.transform.x) / this.transform.k;
        this.draggedNode.y = (my - this.transform.y) / this.transform.k;
        this.render();
        return;
      }

      if (this.isDragging) {
        this.transform.x += mx - this.lastMouse.x;
        this.transform.y += my - this.lastMouse.y;
        this.lastMouse = { x: mx, y: my };
        this.render();
      } else {
        const worldX = (mx - this.transform.x) / this.transform.k;
        const worldY = (my - this.transform.y) / this.transform.k;
        const prevHover = this.hoveredNode;
        this.hoveredNode = this.findNode(worldX, worldY);
        if (prevHover !== this.hoveredNode) {
          this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'default';
          this.render();
        }
      }
    });

    window.addEventListener('mouseup', () => {
      this.draggedNode = null;
      this.isDragging = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      const newScale = Math.min(Math.max(this.transform.k * zoomFactor, 0.3), 3);
      
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      this.transform.x = mx - (mx - this.transform.x) * (newScale / this.transform.k);
      this.transform.y = my - (my - this.transform.y) * (newScale / this.transform.k);
      this.transform.k = newScale;
      this.render();
    });
  }

  findNode(wx, wy) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const dx = n.x - wx;
      const dy = n.y - wy;
      if (dx * dx + dy * dy <= (n.radius + 5) * (n.radius + 5)) {
        return n;
      }
    }
    return null;
  }

  zoomIn() {
    this.transform.k = Math.min(this.transform.k * 1.25, 3);
    this.render();
  }

  zoomOut() {
    this.transform.k = Math.max(this.transform.k * 0.8, 0.3);
    this.render();
  }

  resetView() {
    this.transform = { x: 0, y: 0, k: 1 };
    this.render();
  }
}
