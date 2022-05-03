

class AssertRaises:
    def __init__(self, exception_type):
        if not issubclass(exception_type, BaseException):
            raise TypeError(f"Exception_type {exception_type.__name__} is not subclass of "
                            "BaseException.")
        self.exception_type = exception_type

    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.exception_type == exc_type:
            return True

        raise AssertionError(f"{self.exception_type.__name__} was not raised.") from exc_val


def run_tests():
    # Test that it succeeds when exception is raised.
    try:
        with AssertRaises(ValueError):
            raise ValueError
    except ValueError:
        assert False

    # Test that it raises when exception is not raised.
    try:
        with AssertRaises(ValueError):
            pass
        raise Exception  # The AssertRaises raises AssertionError, for failure raising Exception.
    except AssertionError:
        pass

    # Tests that passing anything else than Exception type fails.
    try:
        with AssertRaises("Not a Exception type"):
            assert False
    except TypeError:
        pass

    try:
        with AssertRaises(Exception("This is instance, not class.")):
            assert False
    except TypeError:
        pass

    try:
        with AssertRaises(int):
            assert False
    except TypeError:
        pass

    # Tests that it does not catch another exception.
    try:
        with AssertRaises(ValueError):
            raise KeyError
        raise Exception  # The AssertRaises raises AssertionError, for failure raising Exception.
    except (AssertionError, KeyError):
        pass


if __name__ == "__main__":
    run_tests()
