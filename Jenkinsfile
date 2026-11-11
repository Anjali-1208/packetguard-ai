// Declarative pipeline. Agent needs: Docker CLI (daemon access), kubectl (with a kubeconfig credential).
// Jenkins credentials expected: 'registry-creds' (username/password), 'kubeconfig' (secret file).
pipeline {
  agent any
  options { timestamps(); disableConcurrentBuilds() }
  parameters {
    string(name: 'REGISTRY', defaultValue: 'docker.io/your-user', description: 'Container registry namespace')
    booleanParam(name: 'DEPLOY', defaultValue: true, description: 'Deploy to Kubernetes after push')
    booleanParam(name: 'FAIL_ON_CRITICAL_CVE', defaultValue: false, description: 'Fail the build if Trivy finds CRITICAL vulnerabilities')
  }
  environment {
    TAG = "${env.BUILD_NUMBER}"
    SERVICES = 'backend frontend ml-service sniffer'
  }
  stages {
    stage('Checkout') { steps { checkout scm } }

    stage('Lint & Unit Tests') {
      parallel {
        stage('Backend') {
          steps { sh '''docker run --rm -v "$PWD/backend:/app" -w /app node:24-slim sh -c "npm install --no-audit --no-fund && node --check src/index.js && npm test"''' }
        }
        stage('Frontend build') {
          steps { sh '''docker run --rm -v "$PWD/frontend:/app" -w /app node:24-slim sh -c "npm install --no-audit --no-fund && npm run build"''' }
        }
        stage('Python (ML + sniffer)') {
          steps { sh '''docker run --rm -v "$PWD:/repo" -w /repo python:3.12-slim sh -c "apt-get update -qq && apt-get install -y -qq libgomp1 >/dev/null && pip install -q -r ml-service/requirements.txt flake8 && flake8 --select=E9,F63,F7,F82 shared sniffer ml-service && pytest -q tests"''' }
        }
      }
    }

    stage('Build Docker Images') {
      steps {
        sh '''
          docker build -t $REGISTRY/packetguard-backend:$TAG   ./backend
          docker build -t $REGISTRY/packetguard-frontend:$TAG  ./frontend
          docker build -t $REGISTRY/packetguard-ml-service:$TAG -f ml-service/Dockerfile .
          docker build -t $REGISTRY/packetguard-sniffer:$TAG   -f sniffer/Dockerfile .
        '''
      }
    }

    stage('Security & Dependency Scan') {
      steps {
        script {
          def code = params.FAIL_ON_CRITICAL_CVE ? 1 : 0
          for (s in env.SERVICES.split(' ')) {
            sh "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity CRITICAL --exit-code ${code} --no-progress ${params.REGISTRY}/packetguard-${s}:${env.TAG}"
          }
        }
      }
    }

    stage('Push to Registry') {
      steps {
        withCredentials([usernamePassword(credentialsId: 'registry-creds', usernameVariable: 'U', passwordVariable: 'P')]) {
          sh '''
            echo "$P" | docker login -u "$U" --password-stdin
            for s in $SERVICES; do docker push $REGISTRY/packetguard-$s:$TAG; done
          '''
        }
      }
    }

    stage('Deploy to Kubernetes') {
      when { expression { params.DEPLOY } }
      steps {
        withCredentials([file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')]) {
          sh '''
            kubectl apply -f k8s/00-namespace-config.yaml -f k8s/10-data.yaml -f k8s/20-apps.yaml
            kubectl -n packetguard set image deploy/backend    backend=$REGISTRY/packetguard-backend:$TAG
            kubectl -n packetguard set image deploy/frontend   frontend=$REGISTRY/packetguard-frontend:$TAG
            kubectl -n packetguard set image deploy/ml-service ml-service=$REGISTRY/packetguard-ml-service:$TAG
            kubectl -n packetguard set image deploy/sniffer    sniffer=$REGISTRY/packetguard-sniffer:$TAG
            for d in backend frontend ml-service sniffer; do kubectl -n packetguard rollout status deploy/$d --timeout=300s; done
          '''
        }
      }
    }

    stage('Smoke Test') {
      when { expression { params.DEPLOY } }
      steps {
        withCredentials([file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')]) {
          sh '''
            kubectl -n packetguard run smoke-$BUILD_NUMBER --rm -i --restart=Never --image=curlimages/curl -- \
              sh -c "curl -fsS http://backend:5000/health && curl -fsS http://ml-service:8000/health && curl -fsS http://frontend/health"
          '''
        }
      }
    }
  }
  post {
    always { sh 'docker image prune -f || true' }
    success { echo "Build ${env.BUILD_NUMBER} deployed." }
    failure { echo 'Pipeline failed — see stage logs.' }
  }
}
