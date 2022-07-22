use rand::Rng;

const MAP_N: usize = 25;

fn main() {
    let mut rng = rand::thread_rng();

    // 配列を定義する際は、[初期値; 要素数]
    // 下は二次元配列なので、[[初期値; 要素数]; 要素数]
    let mut maze = [[0; MAP_N]; MAP_N];

    for n in 0..MAP_N {
        maze[n][0] = 1;
        maze[0][n] = 1;
        maze[n][MAP_N - 1] = 1;
        maze[MAP_N - 1][n] = 1;
    }

    for y in 2..MAP_N - 2 {
        for x in 2..MAP_N - 2 {
            if x % 2 == 1 || y % 2 == 1 {
                continue;
            }

            maze[y][x] = 1;

            // 0~3 のランダム値を生成
            let r = rng.gen_range(0..=3);

            match r {
                0 => maze[y - 1][x] = 1, // 上
                1 => maze[y + 1][x] = 1, // 下
                2 => maze[y][x - 1] = 1, // 右
                3 => maze[y][x + 1] = 1, // 左
                _ => {}
            }
        }
    }

    let tiles = ["  ", "ZZ"];

    for y in 0..MAP_N {
        for x in 0..MAP_N {
            print!("{}", tiles[maze[x][y]]);
        }
        println!("");
    }
}
