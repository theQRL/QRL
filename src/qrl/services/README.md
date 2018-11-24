grpc_tools turns the .proto files in protos/ into \_pb2.py files in generated/. It also generates Python \*APIServicer classes so that you can use GRPC from Python. These are in the \_pb2_grpc.py files. These classes only describe the API endpoints, but not the implementation.


So the \*Service.py files in this directory define what each API endpoint actually does. Starting all of them is handled in services.py.start_services(), which is used in src/qrl/main.py.