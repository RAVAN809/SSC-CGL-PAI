// All external API configurations
export const API_CONFIGS = {
  selectionway: {
    name: 'Selection Way',
    baseUrl: 'https://selection-way.vercel.app',
    requiresAuth: true,
    batchIdParam: 'id', // Batch ID parameter name
    endpoints: {
      batches: '/batches',
      batchFull: '/batch/:id/full',
      batchToday: '/batch/:id/today'
    },
    pathMapping: {
      '/batches': '/batches',
      '/batch/:id/full': '/batch/:id/full',
      '/batch/:id/today': '/batch/:id/today'
    }
  },
  
  rwawebfree: {
    name: 'RWA Web Free',
    baseUrl: 'https://rwawebfree.vercel.app/api',
    requiresAuth: true,
    batchIdParam: 'courseid',
    endpoints: {
      mycourse: '/proxy?endpoint=/get/mycoursev2?',
      subjects: '/proxy?endpoint=/get/allsubjectfrmlivecourseclass?',
      topics: '/proxy?endpoint=/get/alltopicfrmlivecourseclass?',
      content: '/proxy?endpoint=/get/livecourseclassbycoursesubtopconceptapiv3?',
      videoDetails: '/proxy?endpoint=/get/fetchVideoDetailsById?'
    },
    pathMapping: {
      '/proxy': '/proxy'
    }
  },
  
  spidyrwa: {
    name: 'Spidy Universe RWA',
    baseUrl: 'https://spidyuniverserwa.netlify.app/.netlify/functions/api',
    requiresAuth: true,
    endpoints: {
      batches: '/?action=batches',
      today: '/?action=today',
      updates: '/?action=updates'
    },
    pathMapping: {
      '/': '/'
    }
  },
  
  kgs: {
    name: 'KGS Free Lennister',
    baseUrl: 'https://kgsfreelennister.vercel.app/api',
    requiresAuth: true,
    endpoints: {
      proxy: '/proxy'
    },
    pathMapping: {
      '/proxy': '/proxy'
    }
  },
  
  Utkarsh: {
    name: 'Utkarsh Classes',
    baseUrl: 'https://utk-batches-api-63bad375dd0d.herokuapp.com/api',
    requiresAuth: false,
    endpoints: {
      batches: '/batches',
      today: '/today/:batch_id',
      full: '/full/:batch_id'
    },
    pathMapping: {
      '/': '/'
    }
  },
  
  khansir: {
    name: 'Khan Sir',
    baseUrl: 'https://kgs-web.onrender.com/api',
    requiresAuth: true,
    batchIdParam: 'batch_id',
    endpoints: {
      today: '/today/:batch_id',
      updates: '/updates/:batch_id',
      classroom: '/classroom/:batch_id',
      timetable: '/timetable/:batch_id',
      lesson: '/lesson/:lesson_id'
    },
    pathMapping: {
      '/': '/',
      '/today/:batch_id': '/today/:batch_id',
      '/updates/:batch_id': '/updates/:batch_id',
      '/classroom/:batch_id': '/classroom/:batch_id',
      '/timetable/:batch_id': '/timetable/:batch_id',
      '/lesson/:id': '/lesson/:id'
    }
  },
  
  careerwill: {
    name: 'Career Will',
    baseUrl: 'https://cw-api-website.vercel.app',
    requiresAuth: true,
    batchIdParam: 'batchid',
    endpoints: {
      batch: '/batch',
      batchById: '/batch/:batch_id',
      batchToday: '/batch?date=today',
      batchFull: '/batch?full=true'
    },
    pathMapping: {
      '/batch': '/batch',
      '/batch/:batch_id': '/batch/:batch_id'
    }
  },
  
  CwVideo: {
    name: 'Career Will Video',
    baseUrl: 'https://cw-vid-virid.vercel.app',
    requiresAuth: true,
    endpoints: {
      videoDetails: '/get_video_details'
    },
    pathMapping: {
      '/get_video_details': '/get_video_details'
    }
  }
};

// API routes mapping
export const API_ROUTES = {
  '/selectionway': 'selectionway',
  '/rwawebfree': 'rwawebfree',
  '/spidyrwa': 'spidyrwa',
  '/kgs': 'kgs',
  '/Utkarsh': 'Utkarsh',
  '/khansir': 'khansir',
  '/careerwill': 'careerwill',
  '/CwVideo': 'CwVideo'
};

// Batch ID extractors for each API
export const BATCH_ID_EXTRACTORS = {
  selectionway: (req) => {
    const match = req.path.match(/\/batch\/([^\/]+)/);
    return match ? match[1] : null;
  },
  rwawebfree: (req) => {
    return req.query.courseid || req.body.courseid;
  },
  khansir: (req) => {
    const match = req.path.match(/\/(today|updates|classroom|timetable)\/([^\/]+)/);
    return match ? match[2] : req.params.batch_id;
  },
  careerwill: (req) => {
    return req.query.batchid || req.params.batch_id;
  },
  Utkarsh: (req) => {
    return req.params.batch_id || req.query.batch_id;
  }
};