import { create } from 'zustand';

export interface GlobalTask {
    id: string;
    title: string;
    progress: number;
    status: 'pending' | 'running' | 'completed' | 'failed';
    type: 'backup' | 'upload' | 'install';
    icon?: string;
}

interface TaskStore {
    tasks: GlobalTask[];
    addTask: (task: Omit<GlobalTask, 'id' | 'status' | 'progress'>) => string;
    updateTask: (id: string, updates: Partial<GlobalTask>) => void;
    removeTask: (id: string) => void;
}

export const useTaskStore = create<TaskStore>((set) => ({
    tasks: [],
    addTask: (task) => {
        const id = `task_${Date.now()}`;
        set((state) => ({ 
            tasks: [...state.tasks, { ...task, id, status: 'running', progress: 0 }] 
        }));
        return id;
    },
    updateTask: (id, updates) => set((state) => ({
        tasks: state.tasks.map((t) => t.id === id ? { ...t, ...updates } : t)
    })),
    removeTask: (id) => set((state) => ({
        tasks: state.tasks.filter((t) => t.id !== id)
    })),
}));
