import 'operation.dart';

class OperationFeesSetter {
  final Operation operation;

  static const _baseOperationMinimalFee = 100;
  static const _gasBuffer = 100;
  static const _minimalFeePerByte = 1;
  static const _minimalFeePerGas = 0.1;

  OperationFeesSetter(this.operation);

  Future<void> execute() async {
    operation.fee = await totalCost;
  }

  Future<int> get burnFee async {
    return (operation.storageLimit * await costPerBytes).ceil();
  }

  Future<int> get costPerBytes async {
    return int.parse((await operation.operationsList.rpcInterface.constants())['cost_per_byte']);
  }

  int get minimalFee {
    return (_baseOperationMinimalFee + operationFee).ceil();
  }

  int get operationFee {
    return ((operation.gasLimit + _gasBuffer) * _minimalFeePerGas + operationSize * _minimalFeePerByte).ceil();
  }

  // TODO: Why divide by two ?
  int get operationSize {
    final operationsList = operation.operationsList;

    return (operationsList.result.forgedOperation.length / 2 / operationsList.operations.length).ceil();
  }

  Future<int> get totalCost async {
    return (await burnFee) + minimalFee;
  }
}
