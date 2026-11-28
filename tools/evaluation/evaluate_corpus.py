# Purpose: Run with python -m tools.evaluation.evaluate_corpus.
# Works with: lab.corpus_evaluation
# Used by: the Python module loader or CLI entry point

"""Run with python -m tools.evaluation.evaluate_corpus."""

from sentinelav.lab.corpus_evaluation import main

if __name__ == '__main__':
    raise SystemExit(main())
