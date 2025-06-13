import { createAndRunTask } from './task-runner';

export async function buildProject() {
  const task = {
    label: 'Build Advanced Code Server',
    type: 'shell' as const,
    command: 'npm run build',
    group: 'build',
    isBackground: false,
    problemMatcher: ['$tsc']
  };
  
  await createAndRunTask(task, '/workspaces/codespaces-blank/code-server-project');
}

export async function startDevelopment() {
  const task = {
    label: 'Start Development Server',
    type: 'shell' as const,
    command: 'npm run dev',
    group: 'build',
    isBackground: true,
    problemMatcher: ['$tsc-watch']
  };
  
  await createAndRunTask(task, '/workspaces/codespaces-blank/code-server-project');
}

export async function startProduction() {
  const task = {
    label: 'Start Production Server',
    type: 'shell' as const,
    command: 'npm start',
    group: 'build',
    isBackground: true
  };
  
  await createAndRunTask(task, '/workspaces/codespaces-blank/code-server-project');
}

export async function dockerBuild() {
  const task = {
    label: 'Build Docker Containers',
    type: 'shell' as const,
    command: 'docker-compose build',
    group: 'build',
    isBackground: false
  };
  
  await createAndRunTask(task, '/workspaces/codespaces-blank/code-server-project');
}

export async function dockerRun() {
  const task = {
    label: 'Run Docker Containers',
    type: 'shell' as const,
    command: 'docker-compose up -d',
    group: 'build',
    isBackground: true
  };
  
  await createAndRunTask(task, '/workspaces/codespaces-blank/code-server-project');
}
