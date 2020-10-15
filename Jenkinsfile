#!groovy
// -*- mode: groovy -*-

build('bouncer-policies', 'docker-host') {

  checkoutRepo()
  loadBuildUtils()

  def pipeDefault
  runStage('load pipeline') {
    env.JENKINS_LIB = "build_utils/jenkins_lib"
    pipeDefault = load("${env.JENKINS_LIB}/pipeDefault.groovy")
  }

  pipeDefault() {

    runStage('bake manifest') {
      sh "make manifest"
    }

    runStage('validate test fixtures') {
      withGithubPrivkey {
        sh "make -s wc_validate"
      }
    }

    runStage('test policies') {
      sh "make test"
    }

    runStage('build image') {
      sh "make build_image"
    }

    try {
      if (masterlikeBranch()) {
        runStage('push image') {
          sh "make push_image"
        }
      }
    } finally {
      runStage('remove local image') {
        sh 'make rm_local_image'
      }
    }

  }

}
