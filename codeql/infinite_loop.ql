import cpp

from FunctionCall function_call
where function_call.getTarget().getName() = function_call.getBasicBlock().getEnclosingFunction().getName()
select function_call