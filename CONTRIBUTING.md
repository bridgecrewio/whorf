# Contributing

The developer guide is for anyone wanting to contribute directly to the `whorf` project.


## Work locally

To work locally you either need access to a remote Kubernetes cluster or setup one locally via [minikube](https://minikube.sigs.k8s.io/docs/start/) or similar and [kubectl](https://kubernetes.io/docs/tasks/tools/) to interact with the cluster.

Then you can deploy the Kubernetes manifest via the `setup.sh` script by leveraging the local development mode.
```shell
 WHORF_LOCAL=true ./setup.sh [cluster name] [api key]
```

This will create a `local` folder with all the templates adjusted to given inputs.

> **Note**
>
> If `minikube start` results in an error like this
> ```shell
> [kubelet-check] Initial timeout of 40s passed.
>
> Unfortunately, an error has occurred:
> 	timed out waiting for the condition
>
> ...
> ```
>
> then rerunning it with setting an older Kubernetes version may help
> ```shell
> minikube delete --all
> minikube start --kubernetes-version='1.24.9'
> ```

### Image

If you want to test your own version of the container image, then first build the image.

> **Note**
>
> If `minikube` is used, then you need to reuse its built-in Docker daemon
> ```shell
> eval $(minikube docker-env)
> docker build -t whorf .
> ```

Adjust the `image` and `imagePullPolicy` in the `deployment.yaml` in your `local` folder.

ex.
```yaml
    spec:
      containers:
      - name: webhook
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
        image: whorf            # <-- change here
        imagePullPolicy: Never  # <-- change here
        resources:
          ...
```

and redeploy it
```shell
kubectl apply -f local/deployment.yaml
```

> **Note**
>
> If only the image itself changed, then you need to restart the deployment rollout
> ```shell
> kubectl rollout restart deploy validation-webhook -n bridgecrew
> ```

### Logs

To see the logs of the container in tail mode
```shell
kubectl logs -f -l app=validate -n bridgecrew
```

### Test deployment

To easily test, if the admission controller is working as expected, just deploy the local `tests/nginx.yaml` and you will get following response
```shell
kubectl apply -f tests/nginx.yaml

Error from server: error when creating "nginx.yaml": admission webhook "validate.bridgecrew.svc" denied the request: Checkov found 4 issues in violation of admission policy.
CKV_K8S_16:
  Description: Container should not be privileged
  Guidance: https://docs.bridgecrew.io/docs/bc_k8s_15
CKV_K8S_21:
  Description: The default namespace should not be used
  Guidance: https://docs.bridgecrew.io/docs/bc_k8s_20
CKV_K8S_23:
  Description: Minimize the admission of root containers
  Guidance: https://docs.bridgecrew.io/docs/bc_k8s_22
CKV_K8S_20:
  Description: Containers should not run with allowPrivilegeEscalation
  Guidance: https://docs.bridgecrew.io/docs/bc_k8s_19
Checkov found 76 total issues in this manifest.
Checkov found 43 CVEs in container images of which are 2 critical, 1 high, 6 medium and 34 low.
Checkov found 17 license violations in container images.
```

## Work locally without Kubernetes

Since the container image runs a Gunicorn web server with a Flask application you can just startup the Flask application locally and invoke the endpoint via `curl` or similar.

> **Note**
>
> When using PyCharm Professional then you can  easily configure a [Flask Server run configuration](https://www.jetbrains.com/help/pycharm/run-debug-configuration-flask-server.html).
>
> When using PyCharm CE then you can use this run configuration and just need to adjust the `SCRIPT_NAME` to point it against your virtual env path
> ```xml
> <component name="ProjectRunConfigurationManager">
>   <configuration default="false" name="run-flask" type="PythonConfigurationType" factoryName="Python">
>     <module name="whorf" />
>     <option name="INTERPRETER_OPTIONS" value="" />
>     <option name="PARENT_ENVS" value="true" />
>     <envs>
>       <env name="PYTHONUNBUFFERED" value="1" />
>       <env name="FLASK_APP" value="app/whorf.py" />
>       <env name="FLASK_ENV" value="development" />
>       <env name="FLASK_DEBUG" value="1" />
>     </envs>
>     <option name="SDK_HOME" value="" />
>     <option name="WORKING_DIRECTORY" value="$PROJECT_DIR$" />
>     <option name="IS_MODULE_SDK" value="true" />
>     <option name="ADD_CONTENT_ROOTS" value="true" />
>     <option name="ADD_SOURCE_ROOTS" value="true" />
>     <EXTENSION ID="PythonCoverageRunConfigurationExtension" runner="coverage.py" />
>     <option name="SCRIPT_NAME" value="[path to venv]/bin/flask" />
>     <option name="PARAMETERS" value="run" />
>     <option name="SHOW_COMMAND_LINE" value="false" />
>     <option name="EMULATE_TERMINAL" value="false" />
>     <option name="MODULE_MODE" value="false" />
>     <option name="REDIRECT_INPUT" value="false" />
>     <option name="INPUT_FILE" value="" />
>     <method v="2" />
>   </configuration>
> </component>
> ```

Additionally, you need to add the config files for `checkov` and `whorf` to a local `config` folder.

`config/.checkov.yaml`
```yaml
branch: master
repo-id: k8sac/cluster
framework: kubernetes
hard-fail-on:
- CKV_K8S_16
- CKV_K8S_20
- CKV_K8S_23
```

`config/whorf.yaml`
```yaml
ignores-namespaces:
  - bridgecrew
  - kube-system
upload-interval-in-min: 5
```

After starting the Flask application you can just invoke the `validate` endpoint with the `request.json` file under the `tests` folder.
```shell
curl -s -X POST --data "@tests/request.json" -H 'Content-Type: application/json' http://127.0.0.1:5000/validate | jq -r .response.status.message

Checkov found 3 issues in violation of admission policy.
CKV_K8S_20:
  Description: Containers should not run with allowPrivilegeEscalation
  Guidance: https://docs.bridgecrew.io/docs/bc_k8s_19
CKV_K8S_16:
  Description: Container should not be privileged
  Guidance: https://docs.bridgecrew.io/docs/bc_k8s_15
CKV_K8S_23:
  Description: Minimize the admission of root containers
  Guidance: https://docs.bridgecrew.io/docs/bc_k8s_22
Checkov found 15 total issues in this manifest.
```
