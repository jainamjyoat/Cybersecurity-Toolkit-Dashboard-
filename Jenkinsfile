pipeline {

    agent any

    stages {

        stage('GitHub Clone') {

            steps {

                git branch: 'main',
                credentialsId: 'github-token',
                url: 'https://github.com/HarshNag1/Cybersecurity-Toolkit-Dashboard-.git'
            }
        }

        stage('Docker Build') {

            steps {
                bat 'docker build -t cyber-recon .'
            }
        }

        stage('Remove Old Container') {

            steps {
                bat 'docker rm -f cyber-container || exit 0'
            }
        }

        stage('Run Container') {

            steps {
                bat 'docker run -d -p 5000:5000 --name cyber-container cyber-recon'
            }
        }
    }
}