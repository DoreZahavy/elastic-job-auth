interface Loc {
    lat: number
    lon: number
}

interface Experience {
    startTime: number
    endTime: number
    company: string
    title: string
}

export interface User { //WithoutPassword
    _id?: string
    email: string
    userName: string
    fullName: string
    loc: Loc
    skills: string[]
    experience: Experience[]
    imgUrl:string
    gender:string
    password?:string
}

// interface UserWithPassword extends UserWithoutPassword {
//     password:string
// }

// export type User = UserWithoutPassword | UserWithPassword

