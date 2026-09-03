from astranyx.analysis.interprocedural import CrossFileTaintEngine
from astranyx.models.ir import (
    IRCall,
    IRFunction,
    IRModule,
    IRVariable,
    SourceLocation,
)


def location(file, line):
    return SourceLocation(file=file, line=line)


def test_traces_source_to_sink_across_files_with_explainable_path():
    controller = IRModule(
        path="controller.php",
        language="php",
        functions=[
            IRFunction(
                name="handle",
                location=location("controller.php", 1),
                parameters=["request"],
                calls=[
                    IRCall(
                        target="fetch_profile",
                        location=location("controller.php", 4),
                        arguments=["request"],
                    )
                ],
            )
        ],
    )
    service = IRModule(
        path="service.php",
        language="php",
        functions=[
            IRFunction(
                name="fetch_profile",
                location=location("service.php", 8),
                parameters=["url"],
                calls=[
                    IRCall(
                        target="wp_remote_get",
                        location=location("service.php", 10),
                        arguments=["url"],
                    )
                ],
            )
        ],
    )

    findings = CrossFileTaintEngine().analyze([controller, service])

    assert len(findings) == 1
    assert findings[0].source == "request"
    assert findings[0].sink == "wp_remote_get"
    assert findings[0].files == ["controller.php", "service.php"]
    assert findings[0].cross_file is True
    assert [step.kind for step in findings[0].path] == [
        "parameter",
        "parameter",
        "call",
    ]


def test_explicit_sanitizer_is_a_flow_barrier():
    module = IRModule(
        path="handler.php",
        language="php",
        functions=[
            IRFunction(
                name="handle",
                location=location("handler.php", 1),
                parameters=["request"],
                calls=[
                    IRCall(
                        target="allowlisted_url",
                        location=location("handler.php", 2),
                        arguments=["request"],
                        metadata={"result": "safe_url", "sanitizer": True},
                    ),
                    IRCall(
                        target="wp_remote_get",
                        location=location("handler.php", 3),
                        arguments=["safe_url"],
                    ),
                ],
            )
        ],
    )

    assert CrossFileTaintEngine().analyze([module]) == []


def test_assignment_and_return_flow_crosses_call_boundary():
    entry = IRModule(
        path="entry.py",
        language="python",
        functions=[
            IRFunction(
                name="entry",
                location=location("entry.py", 1),
                variables=[
                    IRVariable(
                        "payload",
                        location("entry.py", 2),
                        kind="source",
                    )
                ],
                calls=[
                    IRCall(
                        "identity",
                        location("entry.py", 3),
                        ["payload"],
                        metadata={"result": "returned"},
                    ),
                    IRCall("eval", location("entry.py", 4), ["returned"]),
                ],
            )
        ],
    )
    helper = IRModule(
        path="helper.py",
        language="python",
        functions=[
            IRFunction(
                name="identity",
                location=location("helper.py", 1),
                parameters=["value"],
                metadata={"returns": ["output"]},
                variables=[
                    IRVariable(
                        "output",
                        location("helper.py", 2),
                        metadata={"flows_from": ["value"]},
                    )
                ],
            )
        ],
    )

    findings = CrossFileTaintEngine().analyze([entry, helper])

    assert len(findings) == 1
    assert findings[0].sink == "eval"
    assert findings[0].cross_file is True


def test_ambiguous_function_names_are_not_guessed():
    caller = IRModule(
        path="caller.py",
        language="python",
        functions=[
            IRFunction(
                name="entry",
                location=location("caller.py", 1),
                parameters=["request"],
                calls=[IRCall("forward", location("caller.py", 2), ["request"])],
            )
        ],
    )
    duplicate = lambda path: IRModule(
        path=path,
        language="python",
        functions=[IRFunction("forward", location(path, 1), parameters=["value"])],
    )

    assert (
        CrossFileTaintEngine().analyze(
            [caller, duplicate("one.py"), duplicate("two.py")]
        )
        == []
    )


def test_traversal_depth_is_bounded():
    module = IRModule(
        path="bounded.py",
        language="python",
        functions=[
            IRFunction(
                name="entry",
                location=location("bounded.py", 1),
                variables=[
                    IRVariable("payload", location("bounded.py", 2), kind="source"),
                    IRVariable(
                        "copy",
                        location("bounded.py", 3),
                        metadata={"flows_from": ["payload"]},
                    ),
                ],
                calls=[IRCall("eval", location("bounded.py", 4), ["copy"])],
            )
        ],
    )

    assert CrossFileTaintEngine(max_depth=2).analyze([module]) == []
    assert len(CrossFileTaintEngine(max_depth=3).analyze([module])) == 1


def test_empty_custom_sink_set_disables_default_sinks():
    module = IRModule(
        path="custom.py",
        language="python",
        functions=[
            IRFunction(
                name="entry",
                location=location("custom.py", 1),
                parameters=["request"],
                calls=[IRCall("eval", location("custom.py", 2), ["request"])],
            )
        ],
    )

    assert CrossFileTaintEngine(sinks=set()).analyze([module]) == []
