from typing import Protocol, runtime_checkable


#TODO This class is a draft for a potential abstraction (code-wise, not related to actual abstractions in the context of program
#analysis). To discuss if it is worth doing or if we should just keep the code as it is, as this is implementation is a bit complex
#and might not be worth the time.
@runtime_checkable
class AbstractSet(Protocol):

    def abstraction_step() -> None: ...