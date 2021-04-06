import 'package:meta/meta.dart';

import 'operation.dart';

class TransactionOperation extends Operation {
  TransactionOperation({
    @required int amount,
    @required String destination,
  }) : super(
          kind: Kinds.transaction,
          destination: destination,
          amount: amount,
        );
}
