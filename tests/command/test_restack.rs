use branchless::testing::{make_git, GitRunOptions};

/// Remove some of the output from `git rebase`, as it seems to be
/// non-deterministic as to whether or not it appears.
fn remove_rebase_lines(output: String) -> String {
    output
        .lines()
        .filter(|line| !line.contains("First, rewinding head") && !line.contains("Applying:"))
        .map(|line| format!("{}\n", line))
        .collect()
}

#[test]
fn test_restack_amended_commit() -> anyhow::Result<()> {
    let git = make_git()?;

    if !git.supports_committer_date_is_author_date()? {
        return Ok(());
    }

    git.init_repo()?;
    git.run(&["config", "branchless.restack.preserveTimestamps", "true"])?;

    git.detach_head()?;
    git.commit_file("test1", 1)?;
    git.commit_file("test2", 2)?;
    git.commit_file("test3", 3)?;
    git.run(&["checkout", "HEAD^^"])?;
    git.run(&["commit", "--amend", "-m", "amend test1.txt"])?;

    {
        let (stdout, _stderr) = git.run(&["smartlog"])?;
        insta::assert_snapshot!(stdout, @r###"
            O f777ecc9 (master) create initial.txt
            |\
            | @ 024c35ce amend test1.txt
            |
            x 62fc20d2 (rewritten as 024c35ce) create test1.txt
            |
            o 96d1c37a create test2.txt
            |
            o 70deb1e2 create test3.txt
            "###);
    }

    {
        let (stdout, _stderr) = git.run(&["restack"])?;
        let stdout = remove_rebase_lines(stdout);
        insta::assert_snapshot!(stdout, @r###"
        Calling Git for on-disk rebase...
        branchless: <git-executable> rebase --continue
        Finished restacking commits.
        No abandoned branches to restack.
        branchless: <git-executable> checkout 024c35ce32dae6b12e981963465ee8a62b7eff9b
        O f777ecc9 (master) create initial.txt
        |
        @ 024c35ce amend test1.txt
        |
        o 8cd7de68 create test2.txt
        |
        o b9a0491a create test3.txt
        "###);
    }

    Ok(())
}

#[test]
fn test_restack_consecutive_rewrites() -> anyhow::Result<()> {
    let git = make_git()?;

    if !git.supports_committer_date_is_author_date()? {
        return Ok(());
    }

    git.init_repo()?;
    git.run(&["config", "branchless.restack.preserveTimestamps", "true"])?;

    git.detach_head()?;
    git.commit_file("test1", 1)?;
    git.commit_file("test2", 2)?;
    git.commit_file("test3", 3)?;
    git.run(&["checkout", "HEAD^^"])?;
    git.run(&["commit", "--amend", "-m", "amend test1.txt v1"])?;
    git.run(&["commit", "--amend", "-m", "amend test1.txt v2"])?;

    {
        let (stdout, _stderr) = git.run(&["restack"])?;
        let stdout = remove_rebase_lines(stdout);

        insta::assert_snapshot!(stdout, @r###"
        Calling Git for on-disk rebase...
        branchless: <git-executable> rebase --continue
        Finished restacking commits.
        No abandoned branches to restack.
        branchless: <git-executable> checkout 662b451fb905b92404787e024af717ced49e3045
        O f777ecc9 (master) create initial.txt
        |
        @ 662b451f amend test1.txt v2
        |
        o 8e9bbde3 create test2.txt
        |
        o 9dc6dd07 create test3.txt
        "###)
    }

    Ok(())
}

#[test]
fn test_move_abandoned_branch() -> anyhow::Result<()> {
    let git = make_git()?;

    git.init_repo()?;
    git.run(&["config", "branchless.restack.preserveTimestamps", "true"])?;

    git.commit_file("test1", 1)?;
    git.detach_head()?;
    git.run(&["commit", "--amend", "-m", "amend test1.txt v1"])?;
    git.run(&["commit", "--amend", "-m", "amend test1.txt v2"])?;

    {
        let (stdout, _stderr) = git.run(&["restack"])?;
        let stdout = remove_rebase_lines(stdout);
        insta::assert_snapshot!(stdout, @r###"
        No abandoned commits to restack.
        branchless: processing 1 update: branch master
        Finished restacking branches.
        branchless: <git-executable> checkout 662b451fb905b92404787e024af717ced49e3045
        :
        @ 662b451f (master) amend test1.txt v2
        "###);
    }

    Ok(())
}

#[test]
fn test_amended_initial_commit() -> anyhow::Result<()> {
    let git = make_git()?;

    if !git.supports_committer_date_is_author_date()? {
        return Ok(());
    }

    git.init_repo()?;
    git.run(&["config", "branchless.restack.preserveTimestamps", "true"])?;

    git.commit_file("test1", 1)?;
    git.run(&["checkout", "HEAD^"])?;
    git.run(&["commit", "--amend", "-m", "new initial commit"])?;

    {
        let (stdout, _stderr) = git.run(&["smartlog"])?;
        insta::assert_snapshot!(stdout, @r###"
            @ 9a9f929a new initial commit

            X f777ecc9 (rewritten as 9a9f929a) create initial.txt
            |
            O 62fc20d2 (master) create test1.txt
            "###);
    }

    {
        let (stdout, _stderr) = git.run(&["restack"])?;
        let stdout = remove_rebase_lines(stdout);
        insta::assert_snapshot!(stdout, @r###"
        Calling Git for on-disk rebase...
        branchless: <git-executable> rebase --continue
        Finished restacking commits.
        No abandoned branches to restack.
        branchless: <git-executable> checkout 9a9f929a0d4f052ff5d58bedd97b2f761120f8ed
        @ 9a9f929a new initial commit
        |
        O 6d85943b (master) create test1.txt
        "###);
    }

    Ok(())
}

#[test]
fn test_restack_amended_master() -> anyhow::Result<()> {
    let git = make_git()?;

    if !git.supports_committer_date_is_author_date()? {
        return Ok(());
    }

    git.init_repo()?;
    git.run(&["config", "branchless.restack.preserveTimestamps", "true"])?;

    git.commit_file("test1", 1)?;
    git.commit_file("test2", 2)?;
    git.detach_head()?;
    git.run(&["checkout", "HEAD^"])?;
    git.run(&["commit", "--amend", "-m", "amended test1"])?;

    {
        let (stdout, _stderr) = git.run(&["restack"])?;
        let stdout = remove_rebase_lines(stdout);
        insta::assert_snapshot!(stdout, @r###"
        Calling Git for on-disk rebase...
        branchless: <git-executable> rebase --continue
        Finished restacking commits.
        No abandoned branches to restack.
        branchless: <git-executable> checkout ae94dc2a748bc0965c88fcf3edac2e30074ff7e2
        :
        @ ae94dc2a amended test1
        |
        O 51452b55 (master) create test2.txt
        "###);
    }

    Ok(())
}

#[test]
fn test_restack_aborts_during_rebase_conflict() -> anyhow::Result<()> {
    let git = make_git()?;

    git.init_repo()?;
    git.run(&["branch", "foo"])?;
    git.commit_file("test1", 1)?;
    git.commit_file("test2", 2)?;
    git.run(&["prev"])?;

    git.write_file("test2", "conflicting test2 contents")?;
    git.run(&["add", "."])?;
    git.run(&["commit", "--amend", "-m", "amend test1 with test2 conflict"])?;
    git.run_with_options(
        &["restack"],
        &GitRunOptions {
            expected_exit_code: 1,
            ..Default::default()
        },
    )?;

    Ok(())
}

#[test]
fn test_restack_multiple_amended() -> anyhow::Result<()> {
    let git = make_git()?;

    git.init_repo()?;
    git.detach_head()?;
    git.commit_file("test1", 1)?;
    git.commit_file("test2", 2)?;
    git.commit_file("test3", 3)?;
    git.commit_file("test4", 4)?;

    git.run(&["checkout", "HEAD~"])?;
    git.run(&["commit", "--amend", "-m", "test3 amended"])?;
    git.run(&["checkout", "HEAD~"])?;
    git.run(&["commit", "--amend", "-m", "test2 amended"])?;
    git.run(&["checkout", "HEAD~"])?;

    {
        let (stdout, _stderr) = git.run(&["restack"])?;
        insta::assert_snapshot!(stdout, @r###"
        Calling Git for on-disk rebase...
        branchless: <git-executable> rebase --continue
        Finished restacking commits.
        No abandoned branches to restack.
        branchless: <git-executable> checkout 62fc20d2a290daea0d52bdc2ed2ad4be6491010e
        O f777ecc9 (master) create initial.txt
        |
        @ 62fc20d2 create test1.txt
        |
        o 22f39285 test2 amended
        |
        o 2fdee375 test3 amended
        |
        o c2dfde02 create test4.txt
        "###);
    }

    Ok(())
}

#[test]
fn test_restack_single_of_many_commits() -> anyhow::Result<()> {
    let git = make_git()?;

    if !git.supports_reference_transactions()? {
        return Ok(());
    }

    git.init_repo()?;
    let test1_oid = git.commit_file("test1", 1)?;
    git.detach_head()?;
    let test2_oid = git.commit_file("test2", 2)?;
    git.commit_file("test3", 3)?;
    git.run(&["checkout", &test1_oid.to_string()])?;
    let test4_oid = git.commit_file("test4", 4)?;
    git.commit_file("test5", 5)?;

    git.run(&["checkout", &test2_oid.to_string()])?;
    git.run(&["commit", "--amend", "-m", "updated test2"])?;

    git.run(&["checkout", &test4_oid.to_string()])?;
    git.run(&["commit", "--amend", "-m", "updated test4"])?;

    {
        let (stdout, _stderr) = git.run(&["smartlog"])?;
        insta::assert_snapshot!(stdout, @r###"
        :
        O 62fc20d2 (master) create test1.txt
        |\
        | @ 3bd716d5 updated test4
        |\
        | o 7357d2b7 updated test2
        |\
        | x 96d1c37a (rewritten as 7357d2b7) create test2.txt
        | |
        | o 70deb1e2 create test3.txt
        |
        x bf0d52a6 (rewritten as 3bd716d5) create test4.txt
        |
        o 848121cb create test5.txt
        "###);
    }

    {
        let (stdout, stderr) = git.run(&["restack", &test2_oid.to_string()])?;
        insta::assert_snapshot!(stderr, @r###"
        Executing: git branchless hook-register-extra-post-rewrite-hook
        branchless: processing 1 update: ref HEAD
        branchless: processing 1 update: ref HEAD
        branchless: processed commit: bb7d4b2a create test3.txt
        Executing: git branchless hook-detect-empty-commit 70deb1e28791d8e7dd5a1f0c871a51b91282562f
        branchless: processing 1 rewritten commit
        branchless: <git-executable> checkout 3bd716d57489779ab1daf446f80e66e90b56ead7
        Previous HEAD position was bb7d4b2 create test3.txt
        branchless: processing 1 update: ref HEAD
        HEAD is now at 3bd716d updated test4
        branchless: processing checkout
        Successfully rebased and updated detached HEAD.
        branchless: processing 1 update: ref HEAD
        HEAD is now at 3bd716d updated test4
        branchless: processing checkout
        "###);
        insta::assert_snapshot!(stdout, @r###"
        Calling Git for on-disk rebase...
        branchless: <git-executable> rebase --continue
        Finished restacking commits.
        No abandoned branches to restack.
        branchless: <git-executable> checkout 3bd716d57489779ab1daf446f80e66e90b56ead7
        :
        O 62fc20d2 (master) create test1.txt
        |\
        | @ 3bd716d5 updated test4
        |\
        | o 7357d2b7 updated test2
        | |
        | o bb7d4b2a create test3.txt
        |
        x bf0d52a6 (rewritten as 3bd716d5) create test4.txt
        |
        o 848121cb create test5.txt
        "###);
    }

    Ok(())
}
